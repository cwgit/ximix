/**
 * Copyright 2013 Crypto Workshop Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cryptoworkshop.ximix.mixnet.service;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.FutureTask;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERUTF8String;
import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.config.ConfigException;
import org.cryptoworkshop.ximix.common.config.ConfigObjectFactory;
import org.cryptoworkshop.ximix.common.message.BoardDetails;
import org.cryptoworkshop.ximix.common.message.BoardDownloadMessage;
import org.cryptoworkshop.ximix.common.message.BoardErrorStatusMessage;
import org.cryptoworkshop.ximix.common.message.BoardMessage;
import org.cryptoworkshop.ximix.common.message.BoardStatusMessage;
import org.cryptoworkshop.ximix.common.message.BoardUploadBlockMessage;
import org.cryptoworkshop.ximix.common.message.BoardUploadIndexedMessage;
import org.cryptoworkshop.ximix.common.message.BoardUploadMessage;
import org.cryptoworkshop.ximix.common.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.message.ClientMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.MessageType;
import org.cryptoworkshop.ximix.common.message.PermuteAndMoveMessage;
import org.cryptoworkshop.ximix.common.message.PostedMessageBlock;
import org.cryptoworkshop.ximix.common.message.TransitBoardMessage;
import org.cryptoworkshop.ximix.common.service.BasicService;
import org.cryptoworkshop.ximix.common.service.Decoupler;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;
import org.cryptoworkshop.ximix.mixnet.board.BulletinBoard;
import org.cryptoworkshop.ximix.mixnet.board.BulletinBoardBackupListener;
import org.cryptoworkshop.ximix.mixnet.board.BulletinBoardChangeListener;
import org.cryptoworkshop.ximix.mixnet.board.BulletinBoardImpl;
import org.cryptoworkshop.ximix.mixnet.board.BulletinBoardRegistry;
import org.cryptoworkshop.ximix.mixnet.shuffle.TransformShuffleAndMoveTask;
import org.cryptoworkshop.ximix.mixnet.transform.Transform;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class BoardHostingService
    extends BasicService
{
    private final Executor decoupler;
    private final BulletinBoardRegistry boardRegistry;


    public BoardHostingService(NodeContext nodeContext, Config config)
        throws ConfigException
    {
        super(nodeContext);

        this.decoupler = nodeContext.getDecoupler(Decoupler.SERVICES);

        Map<String, Transform> transforms;

        if (config.hasConfig("transforms"))
        {
            List<TransformConfig> transformList = config.getConfigObjects("transforms", new TransformConfigFactory());

            transforms = transformList.get(0).getTransforms();
        }
        else
        {
            transforms = new HashMap<>();
        }

        BulletinBoardChangeListener changeListener = new BulletinBoardChangeListener()
        {
            @Override
            public void messagesAdded(BulletinBoard bulletinBoard, int count)
            {
                statistics.increment("bhs:add-message-count:" + bulletinBoard.getName(), count);
            }

            @Override
            public void messagesRemoved(BulletinBoardImpl bulletinBoard, int count)
            {
                statistics.increment("bhs:remove-message-count:" + bulletinBoard.getName(), count);
            }

        };


        this.boardRegistry = new BulletinBoardRegistry(nodeContext, transforms, changeListener);

        if (config.hasConfig("boards"))
        {
            List<BoardConfig> boards = config.getConfigObjects("boards", new BoardConfigFactory());

            for (BoardConfig boardConfig : boards)
            {
                BulletinBoard board = boardRegistry.createBoard(boardConfig.getName());

                // Add placeholders for statistics.

                statistics.addPlaceholderValue("bhs:add-message-count:" + boardConfig.getName(), 0);
                statistics.addPlaceholderValue("bhs:remove-message-count:" + boardConfig.getName(), 0);


                for (BackupBoardConfig backupConfig : boardConfig.getBackupBoardConfigs())
                {
                    board.addListener(new BoardRemoteBackupListener(nodeContext, backupConfig));
                }
            }
        }

        statistics.ensurePlaceholders();

    }

    public CapabilityMessage getCapability()
    {
        String[] names = boardRegistry.getBoardNames();
        BoardDetails[] details = new BoardDetails[names.length];

        int count = 0;
        for (String name : names)
        {
            Transform[] transforms = boardRegistry.getTransforms();
            Set<String> transformNames = new HashSet<String>();
            for (Transform transform : transforms)
            {
                transformNames.add(transform.getName());
            }

            details[count++] = new BoardDetails(name, transformNames);
        }

        return new CapabilityMessage(CapabilityMessage.Type.BOARD_HOSTING, details);
    }

    public MessageReply handle(final Message message)
    {
        //
        // we go single threaded here so each message effectively becomes a transaction
        //
        FutureTask<MessageReply> future = new FutureTask<>(new Callable<MessageReply>()
        {
            @Override
            public MessageReply call()
                throws Exception
            {
                return doHandle(message);
            }
        });

        decoupler.execute(future);

        try
        {
            return future.get();
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
        }
        catch (ExecutionException e)
        {
            e.printStackTrace(); // TODO
        }

        return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Future failed to evaluate."));
    }

    private MessageReply doHandle(Message message)
    {
        if (message instanceof CommandMessage)
        {
            switch (((CommandMessage)message).getType())
            {
                case ACTIVATE_BOARD:
                    BoardMessage boardMessage = BoardMessage.getInstance(message.getPayload());
                    boardRegistry.activateBoard(boardMessage.getBoardName());
                    break;
                case SUSPEND_BOARD:
                    boardMessage = BoardMessage.getInstance(message.getPayload());
                    if (boardRegistry.isSuspended(boardMessage.getBoardName()))
                    {
                        return new MessageReply(MessageReply.Type.ERROR, new BoardErrorStatusMessage(boardMessage.getBoardName(), BoardErrorStatusMessage.Status.SUSPENDED));
                    }
                    boardRegistry.suspendBoard(boardMessage.getBoardName());
                    break;
                case BOARD_DOWNLOAD_LOCK:
                    boardMessage = BoardMessage.getInstance(message.getPayload());
                    if (boardRegistry.isLocked(boardMessage.getBoardName()))
                    {
                        return new MessageReply(MessageReply.Type.ERROR, new BoardErrorStatusMessage(boardMessage.getBoardName(), BoardErrorStatusMessage.Status.SUSPENDED));
                    }
                    boardRegistry.downloadLock(boardMessage.getBoardName());
                    break;
                case BOARD_DOWNLOAD_UNLOCK:
                    boardMessage = BoardMessage.getInstance(message.getPayload());
                    boardRegistry.downloadUnlock(boardMessage.getBoardName());
                    break;
                case FETCH_BOARD_STATUS:
                    TransitBoardMessage transitBoardMessage = TransitBoardMessage.getInstance(message.getPayload());
                    if (boardRegistry.isInTransit(transitBoardMessage.getOperationNumber(), transitBoardMessage.getBoardName(), transitBoardMessage.getStepNumber()))
                    {
                        return new MessageReply(MessageReply.Type.OKAY, new BoardStatusMessage(transitBoardMessage.getBoardName(), BoardStatusMessage.Status.IN_TRANSIT));
                    }
                    if (boardRegistry.isComplete(transitBoardMessage.getOperationNumber(), transitBoardMessage.getBoardName(), transitBoardMessage.getStepNumber()))
                    {
                        return new MessageReply(MessageReply.Type.OKAY, new BoardStatusMessage(transitBoardMessage.getBoardName(), BoardStatusMessage.Status.COMPLETE));
                    }
                    return new MessageReply(MessageReply.Type.OKAY, new BoardStatusMessage(transitBoardMessage.getBoardName(), BoardStatusMessage.Status.UNKNOWN));
                case BOARD_SHUFFLE_LOCK:
                    boardMessage = BoardMessage.getInstance(message.getPayload());
                    if (boardRegistry.isLocked(boardMessage.getBoardName()))
                    {
                        return new MessageReply(MessageReply.Type.ERROR, new BoardErrorStatusMessage(boardMessage.getBoardName(), BoardErrorStatusMessage.Status.SUSPENDED));
                    }
                    boardRegistry.shuffleLock(boardMessage.getBoardName());
                    break;
                case BOARD_SHUFFLE_UNLOCK:
                    boardMessage = BoardMessage.getInstance(message.getPayload());
                    boardRegistry.shuffleUnlock(boardMessage.getBoardName());
                    break;
                case START_SHUFFLE_AND_MOVE_BOARD_TO_NODE:
                    final PermuteAndMoveMessage startPandMmessage = PermuteAndMoveMessage.getInstance(message.getPayload());
                    if (!boardRegistry.isShuffleLocked(startPandMmessage.getBoardName()))
                    {
                        return new MessageReply(MessageReply.Type.ERROR, new BoardErrorStatusMessage(startPandMmessage.getBoardName(), BoardErrorStatusMessage.Status.NOT_SHUFFLE_LOCKED));
                    }
                    nodeContext.execute(new StartShuffleTask(nodeContext, boardRegistry, startPandMmessage));
                    break;
                case SHUFFLE_AND_MOVE_BOARD_TO_NODE:
                    PermuteAndMoveMessage pAndmMessage = PermuteAndMoveMessage.getInstance(message.getPayload());
                    nodeContext.execute(new TransformShuffleAndMoveTask(nodeContext, boardRegistry, getPeerConnection(pAndmMessage.getDestinationNode()), CommandMessage.Type.TRANSFER_TO_BOARD, pAndmMessage));
                    break;
                case RETURN_TO_BOARD:
                    transitBoardMessage = TransitBoardMessage.getInstance(message.getPayload());

                    new ReturnToBoardTask(nodeContext, boardRegistry, transitBoardMessage).run();   // in-line for now, note possible synch issues if not.
                    break;
                case INITIATE_INTRANSIT_BOARD:
                    transitBoardMessage = TransitBoardMessage.getInstance(message.getPayload());
                    boardRegistry.markInTransit(transitBoardMessage.getOperationNumber(), transitBoardMessage.getBoardName(), transitBoardMessage.getStepNumber());
                    boardRegistry.getTransitBoard(transitBoardMessage.getOperationNumber(), transitBoardMessage.getBoardName(), transitBoardMessage.getStepNumber()).clear();
                    break;
                case TRANSFER_TO_BOARD:
                    BoardUploadBlockMessage uploadMessage = BoardUploadBlockMessage.getInstance(message.getPayload());

                    boardRegistry.markInTransit(uploadMessage.getOperationNumber(), uploadMessage.getBoardName(), uploadMessage.getStepNumber());
                    boardRegistry.getTransitBoard(uploadMessage.getOperationNumber(), uploadMessage.getBoardName(), uploadMessage.getStepNumber()).postMessageBlock(uploadMessage.getMessageBlock());
                    break;
                case UPLOAD_TO_BOARD:
                    uploadMessage = BoardUploadBlockMessage.getInstance(message.getPayload());

                    boardRegistry.markInTransit(uploadMessage.getOperationNumber(), uploadMessage.getBoardName(), uploadMessage.getStepNumber());
                    boardRegistry.getBoard(uploadMessage.getBoardName()).postMessageBlock(uploadMessage.getMessageBlock());
                    break;
                case CLEAR_BACKUP_BOARD:
                    BoardMessage backupBoardMessage = BoardMessage.getInstance(message.getPayload());
                    // TODO: maybe backup the current backup locally?
                    boardRegistry.getBackupBoard(backupBoardMessage.getBoardName()).clear();
                    break;
                case TRANSFER_TO_BACKUP_BOARD:
                    BoardUploadIndexedMessage uploadIndexedMessage = BoardUploadIndexedMessage.getInstance(message.getPayload());

                    boardRegistry.getBackupBoard(uploadIndexedMessage.getBoardName()).postMessage(uploadIndexedMessage.getData());
                    break;
                case TRANSFER_TO_BOARD_ENDED:
                    transitBoardMessage = TransitBoardMessage.getInstance(message.getPayload());
                    boardRegistry.markCompleted(transitBoardMessage.getOperationNumber(), transitBoardMessage.getBoardName(), transitBoardMessage.getStepNumber());
                    break;
                case DOWNLOAD_BOARD_CONTENTS:
                    BoardDownloadMessage downloadRequest = BoardDownloadMessage.getInstance(message.getPayload());
                    if (!boardRegistry.isDownloadLocked(downloadRequest.getBoardName()))
                    {
                        return new MessageReply(MessageReply.Type.ERROR, new BoardErrorStatusMessage(downloadRequest.getBoardName(), BoardErrorStatusMessage.Status.NOT_DOWNLOAD_LOCKED));
                    }
                    BulletinBoard board = boardRegistry.getBoard(downloadRequest.getBoardName());

                    PostedMessageBlock messages = board.removeMessages(new PostedMessageBlock.Builder(downloadRequest.getMaxNumberOfMessages()));

                    return new MessageReply(MessageReply.Type.OKAY, messages);
                default:
                    return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Unknown command"));
            }
        }
        else
        {
            switch (((ClientMessage)message).getType())
            {
                case UPLOAD_TO_BOARD:
                    BoardUploadMessage uploadMessage = BoardUploadMessage.getInstance(message.getPayload());
                    if (boardRegistry.isLocked(uploadMessage.getBoardName()))
                    {
                        return new MessageReply(MessageReply.Type.ERROR, new BoardErrorStatusMessage(uploadMessage.getBoardName(), BoardErrorStatusMessage.Status.SUSPENDED));
                    }
                    boardRegistry.getBoard(uploadMessage.getBoardName()).postMessage(uploadMessage.getData());
                    break;
                default:
                    return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Unknown command"));
            }
        }
        return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getName()));
    }

    private ServicesConnection getPeerConnection(String destinationNode)
    {
        // return a proxy for ourselves.
        if (nodeContext.getName().equals(destinationNode))
        {
            return new ServicesConnection()
            {
                @Override
                public CapabilityMessage[] getCapabilities()
                {
                    return new CapabilityMessage[] { BoardHostingService.this.getCapability() };
                }

                @Override
                public MessageReply sendMessage(MessageType type, ASN1Encodable messagePayload)
                    throws ServiceConnectionException
                {
                    return BoardHostingService.this.handle(new CommandMessage((CommandMessage.Type)type, messagePayload));
                }

                @Override
                public void close()
                    throws ServiceConnectionException
                {
                    // ignore
                }
            };
        }

        return nodeContext.getPeerMap().get(destinationNode);
    }

    public boolean isAbleToHandle(Message message)
    {
        return new MessageEvaluator(getCapability()).isAbleToHandle(message);
    }

    private static class TransformConfigFactory
        implements ConfigObjectFactory<TransformConfig>
    {
        public TransformConfig createObject(Node configNode)
        {
            return new TransformConfig(configNode);
        }
    }

    private static class TransformConfig
    {
        private Throwable throwable;
        private Map<String, Transform> transforms = new HashMap<>();

        public TransformConfig(Node configNode)
        {
            NodeList xmlNodes = configNode.getChildNodes();

            for (int i = 0; i != xmlNodes.getLength(); i++)
            {
                Node xmlNode = xmlNodes.item(i);

                if (xmlNode.getNodeName().equals("transform"))
                {
                    try
                    {
                        Class clazz = Class.forName(xmlNode.getTextContent().trim());

                        Constructor constructor = clazz.getConstructor();

                        Transform impl = (Transform)constructor.newInstance();

                        transforms.put(impl.getName(), impl);
                    }
                    catch (ClassNotFoundException e)
                    {
                        throwable = e;
                    }
                    catch (NoSuchMethodException e)
                    {
                        throwable = e;
                    }
                    catch (InvocationTargetException e)
                    {
                        throwable = e;
                    }
                    catch (InstantiationException e)
                    {
                        throwable = e;
                    }
                    catch (IllegalAccessException e)
                    {
                        throwable = e;
                    }
                }
            }
        }

        public Map<String, Transform> getTransforms()
        {
            return transforms;
        }
    }


    private static class BoardConfigFactory
        implements ConfigObjectFactory<BoardConfig>
    {
        public BoardConfig createObject(Node configNode)
        {
            return new BoardConfig(configNode);
        }
    }

    private static class BoardConfig
    {
        private String name;
        private List<BackupBoardConfig> backupBoardConfigs = new ArrayList<>();

        public BoardConfig(Node configNode)
        {
            NodeList xmlNodes = configNode.getChildNodes();
            BackupBoardConfigFactory fact = new BackupBoardConfigFactory();

            for (int i = 0; i != xmlNodes.getLength(); i++)
            {
                Node xmlNode = xmlNodes.item(i);

                NodeList innerNodes = xmlNode.getChildNodes();

                for (int j = 0; j != innerNodes.getLength(); j++)
                {
                    Node innerNode = innerNodes.item(j);

                    if ("backup-boards".equals(innerNode.getNodeName()))
                    {
                        backupBoardConfigs.add(fact.createObject(innerNode));
                    }
                    else if (innerNode.getNodeName().equals("name"))
                    {
                        this.name = innerNode.getTextContent();
                    }
                }
            }
        }

        public String getName()
        {
            return name;
        }

        private List<BackupBoardConfig> getBackupBoardConfigs()
        {
            return backupBoardConfigs;
        }
    }


    private static class BackupBoardConfigFactory
        implements ConfigObjectFactory<BackupBoardConfig>
    {
        public BackupBoardConfig createObject(Node configNode)
        {
            return new BackupBoardConfig(configNode);
        }
    }

    private static class BackupBoardConfig
    {
        private String nodeName;

        public BackupBoardConfig(Node configNode)
        {
            NodeList xmlNodes = configNode.getChildNodes();

            for (int i = 0; i != xmlNodes.getLength(); i++)
            {
                Node xmlNode = xmlNodes.item(i);

                NodeList innerNodes = xmlNode.getChildNodes();

                for (int j = 0; j != innerNodes.getLength(); j++)
                {
                    Node innerNode = innerNodes.item(j);

                    if (innerNode.getNodeName().equals("node"))
                    {
                        this.nodeName = innerNode.getTextContent();
                    }
                }
            }
        }

        public String getNodeName()
        {
            return nodeName;
        }
    }

    private class BoardRemoteBackupListener
        implements BulletinBoardBackupListener
    {
        private final NodeContext nodeContext;
        private final BackupBoardConfig backupConfig;

        public BoardRemoteBackupListener(NodeContext nodeContext, BackupBoardConfig backupConfig)
        {
            this.nodeContext = nodeContext;
            this.backupConfig = backupConfig;
        }

        @Override
        public void cleared(BulletinBoard bulletinBoard)
        {
            try
            {
                nodeContext.getPeerMap().get(backupConfig.getNodeName()).sendMessage(CommandMessage.Type.CLEAR_BACKUP_BOARD, new BoardMessage(bulletinBoard.getName()));
            }
            catch (ServiceConnectionException e)
            {
                // TODO:
                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            }
        }

        @Override
        public void messagePosted(BulletinBoard bulletinBoard, int index, byte[] message)
        {
            // TODO: there needs to be an initialisation phase to make sure the backup board is in sync
            try
            {
                nodeContext.getPeerMap().get(backupConfig.getNodeName()).sendMessage(CommandMessage.Type.TRANSFER_TO_BACKUP_BOARD, new BoardUploadIndexedMessage(bulletinBoard.getName(), index, message));
            }
            catch (ServiceConnectionException e)
            {
                // TODO:
                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            }
        }
    }

    private class StartShuffleTask
        implements Runnable
    {
        private final NodeContext nodeContext;
        private final PermuteAndMoveMessage startPandMmessage;
        private final BulletinBoardRegistry boardRegistry;

        public StartShuffleTask(NodeContext nodeContext, BulletinBoardRegistry boardRegistry, PermuteAndMoveMessage startPandMmessage)
        {
            this.nodeContext = nodeContext;
            this.boardRegistry = boardRegistry;
            this.startPandMmessage = startPandMmessage;
        }

        @Override
        public void run()
        {
            try
            {
                boardRegistry.moveToTransit(startPandMmessage.getOperationNumber(), startPandMmessage.getBoardName(), startPandMmessage.getStepNumber());

                new TransformShuffleAndMoveTask(nodeContext, boardRegistry, getPeerConnection(startPandMmessage.getDestinationNode()), CommandMessage.Type.TRANSFER_TO_BOARD, startPandMmessage).run();
            }
            catch (Exception e)
            {
                // TODO:
                e.printStackTrace();
            }
        }
    }

    private class ReturnToBoardTask
        implements Runnable
    {
        private final NodeContext nodeContext;
        private final TransitBoardMessage transitBoardMessage;
        private final BulletinBoardRegistry boardRegistry;

        public ReturnToBoardTask(NodeContext nodeContext, BulletinBoardRegistry boardRegistry, TransitBoardMessage transitBoardMessage)
        {
            this.nodeContext = nodeContext;
            this.boardRegistry = boardRegistry;
            this.transitBoardMessage = transitBoardMessage;
        }

        @Override
        public void run()
        {
            try
            {
                BulletinBoard transitBoard = boardRegistry.getTransitBoard(transitBoardMessage.getOperationNumber(), transitBoardMessage.getBoardName(), transitBoardMessage.getStepNumber());
                BulletinBoard homeBoard = boardRegistry.getBoard(transitBoardMessage.getBoardName());

                while (transitBoard.size() > 0)
                {
                    PostedMessageBlock.Builder messageFetcher = new PostedMessageBlock.Builder(100);

                    transitBoard.removeMessages(messageFetcher);

                    homeBoard.postMessageBlock(messageFetcher.build());
                }
            }
            catch (Exception e)
            {
                // TODO:
                e.printStackTrace();
            }
        }
    }
}
