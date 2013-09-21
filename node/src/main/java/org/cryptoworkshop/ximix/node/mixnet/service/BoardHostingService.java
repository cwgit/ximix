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
package org.cryptoworkshop.ximix.node.mixnet.service;

import java.lang.reflect.Constructor;
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
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERUTF8String;
import org.cryptoworkshop.ximix.client.connection.ServiceConnectionException;
import org.cryptoworkshop.ximix.client.connection.ServicesConnection;
import org.cryptoworkshop.ximix.common.asn1.message.BoardDetails;
import org.cryptoworkshop.ximix.common.asn1.message.BoardDownloadMessage;
import org.cryptoworkshop.ximix.common.asn1.message.BoardErrorStatusMessage;
import org.cryptoworkshop.ximix.common.asn1.message.BoardMessage;
import org.cryptoworkshop.ximix.common.asn1.message.BoardStatusMessage;
import org.cryptoworkshop.ximix.common.asn1.message.BoardUploadBlockMessage;
import org.cryptoworkshop.ximix.common.asn1.message.BoardUploadIndexedMessage;
import org.cryptoworkshop.ximix.common.asn1.message.BoardUploadMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ClientMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.Message;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.MessageType;
import org.cryptoworkshop.ximix.common.asn1.message.PermuteAndMoveMessage;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessage;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessageBlock;
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptBlock;
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptDownloadMessage;
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptQueryMessage;
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptQueryResponse;
import org.cryptoworkshop.ximix.common.asn1.message.TransitBoardMessage;
import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.config.ConfigException;
import org.cryptoworkshop.ximix.common.config.ConfigObjectFactory;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.common.util.TranscriptType;
import org.cryptoworkshop.ximix.node.mixnet.board.BulletinBoard;
import org.cryptoworkshop.ximix.node.mixnet.board.BulletinBoardBackupListener;
import org.cryptoworkshop.ximix.node.mixnet.board.BulletinBoardChangeListener;
import org.cryptoworkshop.ximix.node.mixnet.board.BulletinBoardImpl;
import org.cryptoworkshop.ximix.node.mixnet.board.BulletinBoardRegistry;
import org.cryptoworkshop.ximix.node.mixnet.challenge.SerialChallenger;
import org.cryptoworkshop.ximix.node.mixnet.shuffle.TransformShuffleAndMoveTask;
import org.cryptoworkshop.ximix.node.mixnet.transform.Transform;
import org.cryptoworkshop.ximix.node.mixnet.util.IndexNumberGenerator;
import org.cryptoworkshop.ximix.node.service.BasicNodeService;
import org.cryptoworkshop.ximix.node.service.Decoupler;
import org.cryptoworkshop.ximix.node.service.NodeContext;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class BoardHostingService
    extends BasicNodeService
{
    private final Executor decoupler;
    private final BulletinBoardRegistry boardRegistry;
    private final AtomicLong queryCounter = new AtomicLong(0L);
    private final Constructor witnessChallengerConstructor;
    private final Map<String, IndexNumberGenerator> challengers = new HashMap<>();

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

        if (config.hasConfig("challenger"))
        {
            witnessChallengerConstructor = config.getConfigObject("challenger", new ChallengerFactory());
        }
        else
        {
            try
            {
                witnessChallengerConstructor = SerialChallenger.class.getConstructor(Integer.class, Integer.class);
            }
            catch (NoSuchMethodException e)
            {
                throw new ConfigException("Cannot create witness challenge constructor: " + e.getMessage(), e);
            }
        }

        BulletinBoardChangeListener changeListener = new BulletinBoardChangeListener()
        {
            @Override
            public void messagesAdded(BulletinBoard bulletinBoard, int count)
            {
                statistics.increment("bhs!messages-on-board!" + bulletinBoard.getName(), count);
            }

            @Override
            public void messagesRemoved(BulletinBoardImpl bulletinBoard, int count)
            {
                statistics.decrement("bhs!messages-on-board!" + bulletinBoard.getName(), count);
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

                statistics.addPlaceholderValue("bhs!messages-on-board!" + boardConfig.getName(), 0);

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
            nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, e);
        }

        return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Future failed to evaluate on " + nodeContext.getName()));
    }

    private MessageReply doHandle(Message message)
    {
        if (message instanceof CommandMessage)
        {
            switch (((CommandMessage)message).getType())
            {
            case GET_BOARD_HOST:
                BoardMessage boardMessage = BoardMessage.getInstance(message.getPayload());

                return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getBoardHost(boardMessage.getBoardName())));
            case ACTIVATE_BOARD:
                boardMessage = BoardMessage.getInstance(message.getPayload());
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
            case DOWNLOAD_SHUFFLE_TRANSCRIPT:
                TranscriptDownloadMessage transcriptDownloadMessage = TranscriptDownloadMessage.getInstance(message.getPayload());
                BulletinBoard transitBoard = boardRegistry.getTransitBoard(transcriptDownloadMessage.getOperationNumber(), transcriptDownloadMessage.getStepNo());

                String challengerKey = getChallengerKey(transcriptDownloadMessage);
                IndexNumberGenerator challenger = challengers.get(challengerKey);
                if (challenger == null)
                {
                    if (TranscriptType.GENERAL == transcriptDownloadMessage.getType())
                    {
                        challenger = new SerialChallenger(transitBoard.transcriptSize(TranscriptType.GENERAL), transcriptDownloadMessage.getStepNo());
                    }
                    else
                    {
                        try
                        {
                            challenger = (IndexNumberGenerator)witnessChallengerConstructor.newInstance(transitBoard.transcriptSize(transcriptDownloadMessage.getType()), transcriptDownloadMessage.getStepNo());
                        }
                        catch (Exception e)
                        {
                            nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, e);
                            return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Unable to create challenger on " + nodeContext.getName()));
                        }
                    }
                    challengers.put(challengerKey, challenger);
                }

                TranscriptBlock transcriptBlock = transitBoard.fetchTranscriptData(transcriptDownloadMessage.getType(), challenger, new TranscriptBlock.Builder(transcriptDownloadMessage.getStepNo(), transcriptDownloadMessage.getMaxNumberOfMessages()));

                return new MessageReply(MessageReply.Type.OKAY, transcriptBlock);
            case DOWNLOAD_SHUFFLE_TRANSCRIPT_STEPS:
                TranscriptQueryMessage transcriptQueryMessage = TranscriptQueryMessage.getInstance(message.getPayload());

                List<String> transitBoardNames = boardRegistry.getTransitBoardNames(transcriptQueryMessage.getOperationNumber());
                int[]        stepNos = new int[transitBoardNames.size()];
                String       boardName = "";

                for (int i = 0; i != stepNos.length; i++)
                {
                    String name = transitBoardNames.get(i);
                    boardName = name.substring(name.indexOf('.') + 1, name.lastIndexOf('.'));

                    stepNos[i] = Integer.parseInt(name.substring(name.lastIndexOf('.') + 1));
                }

                return new MessageReply(MessageReply.Type.OKAY, new TranscriptQueryResponse(queryCounter.incrementAndGet(), boardName, stepNos));
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

    private String getChallengerKey(TranscriptDownloadMessage transcriptDownloadMessage)
    {
        return transcriptDownloadMessage.getQueryID() + "." + transcriptDownloadMessage.getStepNo();
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

    private static class ChallengerFactory
        implements ConfigObjectFactory<Constructor>
    {
        private Throwable throwable;

        public Constructor createObject(Node configNode)
            throws ConfigException
        {
            NodeList xmlNodes = configNode.getChildNodes();

            for (int i = 0; i != xmlNodes.getLength(); i++)
            {
                Node xmlNode = xmlNodes.item(i);

                if (xmlNode.getNodeName().equals("implementation"))
                {
                    try
                    {
                        Class clazz = Class.forName(xmlNode.getTextContent().trim());

                        Constructor constructor = clazz.getConstructor(Integer.class, Integer.class);

                        return constructor;
                    }
                    catch (Exception e)
                    {
                        throw new ConfigException("Unable to create Challenger: " + e.getMessage(), e);
                    }
                }
            }

            return null;
        }
    }

    private static class TransformConfigFactory
        implements ConfigObjectFactory<TransformConfig>
    {
        public TransformConfig createObject(Node configNode)
            throws ConfigException
        {
            return new TransformConfig(configNode);
        }
    }

    private static class TransformConfig
    {
        private Map<String, Transform> transforms = new HashMap<>();

        public TransformConfig(Node configNode)
            throws ConfigException
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
                    catch (Exception e)
                    {
                        throw new ConfigException("Unable to create Transform: " + e.getMessage(), e);
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
        public void cleared(final BulletinBoard bulletinBoard)
        {
            nodeContext.getScheduledExecutor().execute(new Runnable()
            {
                @Override
                public void run()
                {
                    try
                    {
                        MessageReply reply = nodeContext.getPeerMap().get(backupConfig.getNodeName()).sendMessage(CommandMessage.Type.CLEAR_BACKUP_BOARD, new BoardMessage(bulletinBoard.getName()));
                        checkForError(reply);
                    }
                    catch (ServiceConnectionException e)
                    {
                        nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Exception on clear backup.", e);
                    }
                }
            });

        }

        @Override
        public void messagePosted(final BulletinBoard bulletinBoard, final int index, final byte[] message)
        {
            // TODO: there needs to be an initialisation phase to make sure the backup board is in sync
            nodeContext.getScheduledExecutor().execute(new Runnable()
            {
                @Override
                public void run()
                {
                    try
                    {
                        MessageReply reply = nodeContext.getPeerMap().get(backupConfig.getNodeName()).sendMessage(CommandMessage.Type.TRANSFER_TO_BACKUP_BOARD, new BoardUploadIndexedMessage(bulletinBoard.getName(), index, message));
                        checkForError(reply);
                    }
                    catch (ServiceConnectionException e)
                    {
                        nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Exception on post to backup.", e);
                    }
                }
            });
        }

        private void checkForError(MessageReply reply)
        {
            if (reply.getType() != MessageReply.Type.OKAY)
            {
                String message = (reply.getPayload() instanceof DERUTF8String) ? DERUTF8String.getInstance(reply.getPayload()).getString() : "no detail";

                nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Error on post to backup: " + message);
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
                PostedMessageBlock.Builder messageFetcher = new PostedMessageBlock.Builder(100);

                int index = 0;
                for (PostedMessage postedMessage : transitBoard)
                {
                    messageFetcher.add(index++, postedMessage.getMessage());

                    if (messageFetcher.isFull())
                    {
                        homeBoard.postMessageBlock(messageFetcher.build());
                        messageFetcher.clear();
                    }
                }

                if (!messageFetcher.isEmpty())
                {
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
