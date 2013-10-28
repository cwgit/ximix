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
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.util.encoders.Hex;
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
import org.cryptoworkshop.ximix.common.asn1.message.CreateBoardMessage;
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
import org.cryptoworkshop.ximix.node.mixnet.board.BulletinBoardRegistry;
import org.cryptoworkshop.ximix.node.mixnet.challenge.SeededChallenger;
import org.cryptoworkshop.ximix.node.mixnet.challenge.SerialChallenger;
import org.cryptoworkshop.ximix.node.mixnet.shuffle.TransformShuffleAndMoveTask;
import org.cryptoworkshop.ximix.node.mixnet.transform.Transform;
import org.cryptoworkshop.ximix.node.mixnet.util.IndexNumberGenerator;
import org.cryptoworkshop.ximix.node.service.BasicNodeService;
import org.cryptoworkshop.ximix.node.service.Decoupler;
import org.cryptoworkshop.ximix.node.service.NodeContext;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Service class for hosting bulletin boards.
 */
public class BoardHostingService
    extends BasicNodeService
{
    private final Executor decoupler;
    private final BulletinBoardRegistry boardRegistry;
    private final AtomicLong queryCounter = new AtomicLong(0L);
    private final Constructor witnessChallengerConstructor;
    private final Map<String, IndexNumberGenerator> challengers = new HashMap<>();
    private final BoardExecutor boardExecutor;

    /**
     * Base constructor.
     *
     * @param nodeContext the context for the node we are in.
     * @param config source of config information if required.
     */
    public BoardHostingService(NodeContext nodeContext, Config config)
        throws ConfigException
    {
        super(nodeContext);

        this.decoupler = nodeContext.getDecoupler(Decoupler.SERVICES);

        this.boardExecutor = new BoardExecutor(decoupler, nodeContext.getScheduledExecutor());

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
                witnessChallengerConstructor = SeededChallenger.class.getConstructor(Integer.class, Integer.class, byte[].class);
            }
            catch (NoSuchMethodException e)
            {
                throw new ConfigException("Cannot create witness challenge constructor: " + e.getMessage(), e);
            }
        }

        this.boardRegistry = new BulletinBoardRegistry(nodeContext, transforms, statistics);

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
        FutureTask<MessageReply> future = submitToHandle(message);

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

    private FutureTask<MessageReply> submitToHandle(Message message)
    {
        if (message instanceof CommandMessage)
        {
            switch (((CommandMessage)message).getType())
            {
            case GET_BOARD_HOST:
                final BoardMessage boardMessage = BoardMessage.getInstance(message.getPayload());

                return boardExecutor.submitTask(boardMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        String boardHost = nodeContext.getBoardHost(boardMessage.getBoardName());

                        if (boardHost != null)
                        {
                            return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(boardHost));
                        }
                        else
                        {
                            return new MessageReply(MessageReply.Type.OKAY, DERNull.INSTANCE);
                        }
                    }
                });
            case ACTIVATE_BOARD:
                final BoardMessage activateBoardMessage = BoardMessage.getInstance(message.getPayload());
                return boardExecutor.submitTask(activateBoardMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        boardRegistry.activateBoard(activateBoardMessage.getBoardName());
                        return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getName()));
                    }
                });
            case SUSPEND_BOARD:
                final BoardMessage suspendBoardMessage = BoardMessage.getInstance(message.getPayload());
                return boardExecutor.submitTask(suspendBoardMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        if (boardRegistry.isSuspended(suspendBoardMessage.getBoardName()))
                        {
                            return new MessageReply(MessageReply.Type.ERROR, new BoardErrorStatusMessage(suspendBoardMessage.getBoardName(), BoardErrorStatusMessage.Status.SUSPENDED));
                        }
                        boardRegistry.suspendBoard(suspendBoardMessage.getBoardName());
                        return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getName()));
                    }
                });
            case BOARD_CREATE:
                final CreateBoardMessage createBoardMessage = CreateBoardMessage.getInstance(message.getPayload());

                return boardExecutor.submitTask(createBoardMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        if (boardRegistry.hasBoard(createBoardMessage.getBoardName()))
                        {
                            return new MessageReply(MessageReply.Type.ERROR, new BoardErrorStatusMessage(createBoardMessage.getBoardName(), BoardErrorStatusMessage.Status.ALREADY_EXISTS));
                        }

                        if (createBoardMessage.getBackUpHost() != null)
                        {
                            boardRegistry.createBoard(createBoardMessage.getBoardName(), createBoardMessage.getBackUpHost());
                        }
                        else
                        {
                            boardRegistry.createBoard(createBoardMessage.getBoardName());
                        }

                        return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getName()));
                    }
                });
            case BACKUP_BOARD_CREATE:
                final BoardMessage backupBoardCreateMessage = BoardMessage.getInstance(message.getPayload());
                return boardExecutor.submitTask(backupBoardCreateMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {

                        boardRegistry.createBackupBoard(backupBoardCreateMessage.getBoardName());

                        return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getName()));
                    }
                });
            case BOARD_DOWNLOAD_LOCK:
                final BoardMessage downloadLockBoardMessage = BoardMessage.getInstance(message.getPayload());
                return boardExecutor.submitTask(downloadLockBoardMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        if (boardRegistry.isLocked(downloadLockBoardMessage.getBoardName()))
                        {
                            return new MessageReply(MessageReply.Type.ERROR, new BoardErrorStatusMessage(downloadLockBoardMessage.getBoardName(), BoardErrorStatusMessage.Status.SUSPENDED));
                        }
                        boardRegistry.downloadLock(downloadLockBoardMessage.getBoardName());
                        return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getName()));
                    }
                });
            case BOARD_DOWNLOAD_UNLOCK:
                final BoardMessage downloadUnlockBoardMessage = BoardMessage.getInstance(message.getPayload());
                return boardExecutor.submitTask(downloadUnlockBoardMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        boardRegistry.downloadUnlock(downloadUnlockBoardMessage.getBoardName());
                        return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getName()));
                    }
                });
            case FETCH_BOARD_STATUS:
                final TransitBoardMessage transitBoardMessage = TransitBoardMessage.getInstance(message.getPayload());
                return boardExecutor.submitTask(transitBoardMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        if (boardRegistry.isInTransit(transitBoardMessage.getOperationNumber(), transitBoardMessage.getBoardName(), transitBoardMessage.getStepNumber()))
                        {
                            return new MessageReply(MessageReply.Type.OKAY, new BoardStatusMessage(transitBoardMessage.getBoardName(), BoardStatusMessage.Status.IN_TRANSIT));
                        }
                        if (boardRegistry.isComplete(transitBoardMessage.getOperationNumber(), transitBoardMessage.getBoardName(), transitBoardMessage.getStepNumber()))
                        {
                            return new MessageReply(MessageReply.Type.OKAY, new BoardStatusMessage(transitBoardMessage.getBoardName(), BoardStatusMessage.Status.COMPLETE));
                        }
                        return new MessageReply(MessageReply.Type.OKAY, new BoardStatusMessage(transitBoardMessage.getBoardName(), BoardStatusMessage.Status.UNKNOWN));
                    }
                });
            case FETCH_BOARD_COMPLETION_STATUS:
                final BoardMessage compStatusBoardMessage = BoardMessage.getInstance(message.getPayload());
                return boardExecutor.submitTask(compStatusBoardMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        if (boardRegistry.isLocked(compStatusBoardMessage.getBoardName()))
                        {
                            return new MessageReply(MessageReply.Type.OKAY, new BoardStatusMessage(compStatusBoardMessage.getBoardName(), BoardStatusMessage.Status.IN_TRANSIT));
                        }
                        return new MessageReply(MessageReply.Type.OKAY, new BoardStatusMessage(compStatusBoardMessage.getBoardName(), BoardStatusMessage.Status.COMPLETE));
                    }
                });
            case BOARD_SHUFFLE_LOCK:
                final BoardMessage shuffleLockBoardMessage = BoardMessage.getInstance(message.getPayload());
                return boardExecutor.submitTask(shuffleLockBoardMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        if (boardRegistry.isLocked(shuffleLockBoardMessage.getBoardName()))
                        {
                            return new MessageReply(MessageReply.Type.ERROR, new BoardErrorStatusMessage(shuffleLockBoardMessage.getBoardName(), BoardErrorStatusMessage.Status.SUSPENDED));
                        }
                        boardRegistry.shuffleLock(shuffleLockBoardMessage.getBoardName());
                        return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getName()));
                    }
                });
            case BOARD_SHUFFLE_UNLOCK:
                final BoardMessage shuffleUnlockBoardMessage = BoardMessage.getInstance(message.getPayload());

                return boardExecutor.submitTask(shuffleUnlockBoardMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {

                        boardRegistry.shuffleUnlock(shuffleUnlockBoardMessage.getBoardName());
                        return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getName()));
                    }
                });
            case START_SHUFFLE_AND_MOVE_BOARD_TO_NODE:
                final PermuteAndMoveMessage startPandMmessage = PermuteAndMoveMessage.getInstance(message.getPayload());

                return boardExecutor.submitTask(startPandMmessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        if (!boardRegistry.isShuffleLocked(startPandMmessage.getBoardName()))
                        {
                            return new MessageReply(MessageReply.Type.ERROR, new BoardErrorStatusMessage(startPandMmessage.getBoardName(), BoardErrorStatusMessage.Status.NOT_SHUFFLE_LOCKED));
                        }

                        nodeContext.execute(new StartShuffleTask(nodeContext, boardRegistry, startPandMmessage));

                        return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getName()));
                    }
                });
            case SHUFFLE_AND_MOVE_BOARD_TO_NODE:
                final PermuteAndMoveMessage pAndmMessage = PermuteAndMoveMessage.getInstance(message.getPayload());

                return boardExecutor.submitTask(pAndmMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        nodeContext.execute(new TransformShuffleAndMoveTask(nodeContext, boardRegistry, getPeerConnection(pAndmMessage.getDestinationNode()), pAndmMessage));

                        return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getName()));
                    }
                });
            case RETURN_TO_BOARD:
                final TransitBoardMessage returnToBoardMessage = TransitBoardMessage.getInstance(message.getPayload());

                return boardExecutor.submitTask(returnToBoardMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        nodeContext.execute(new ReturnToBoardTask(nodeContext, boardRegistry, returnToBoardMessage));
                        return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getName()));
                    }
                });
            case INITIATE_INTRANSIT_BOARD:
                final TransitBoardMessage initiateTransitBoardMessage = TransitBoardMessage.getInstance(message.getPayload());

                return boardExecutor.submitTask(initiateTransitBoardMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        boardRegistry.markInTransit(initiateTransitBoardMessage.getOperationNumber(), initiateTransitBoardMessage.getBoardName(), initiateTransitBoardMessage.getStepNumber());
                        boardRegistry.getTransitBoard(initiateTransitBoardMessage.getOperationNumber(), initiateTransitBoardMessage.getBoardName(), initiateTransitBoardMessage.getStepNumber()).clear();
                        return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getName()));
                    }
                });
            case TRANSFER_TO_BOARD:
                final BoardUploadBlockMessage uploadMessage = BoardUploadBlockMessage.getInstance(message.getPayload());

                return boardExecutor.submitTask(uploadMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        boardRegistry.markInTransit(uploadMessage.getOperationNumber(), uploadMessage.getBoardName(), uploadMessage.getStepNumber());
                        boardRegistry.getTransitBoard(uploadMessage.getOperationNumber(), uploadMessage.getBoardName(), uploadMessage.getStepNumber()).postMessageBlock(uploadMessage.getMessageBlock());
                        return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getName()));
                    }
                });
            case UPLOAD_TO_BOARD:
                final BoardUploadBlockMessage uploadToBoardMessage = BoardUploadBlockMessage.getInstance(message.getPayload());

                return boardExecutor.submitTask(uploadToBoardMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                    {
                        boardRegistry.markInTransit(uploadToBoardMessage.getOperationNumber(), uploadToBoardMessage.getBoardName(), uploadToBoardMessage.getStepNumber());
                        boardRegistry.getBoard(uploadToBoardMessage.getBoardName()).postMessageBlock(uploadToBoardMessage.getMessageBlock());

                        return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getName()));
                    }
                });
            case CLEAR_BACKUP_BOARD:
                final BoardMessage backupBoardMessage = BoardMessage.getInstance(message.getPayload());

                return boardExecutor.submitTask(backupBoardMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                    {
                        // TODO: maybe backup the current backup locally?
                        boardRegistry.getBackupBoard(backupBoardMessage.getBoardName()).clear();
                        return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getName()));
                    }
                });
            case TRANSFER_TO_BACKUP_BOARD:
                final BoardUploadIndexedMessage uploadIndexedMessage = BoardUploadIndexedMessage.getInstance(message.getPayload());

                return boardExecutor.submitTask(uploadIndexedMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                    {
                        boardRegistry.getBackupBoard(uploadIndexedMessage.getBoardName()).postMessages(uploadIndexedMessage.getData());
                        return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getName()));
                    }
                });
            case TRANSFER_TO_BOARD_ENDED:
                final TransitBoardMessage transferToBoardEndedMessage = TransitBoardMessage.getInstance(message.getPayload());

                return boardExecutor.submitTask(transferToBoardEndedMessage.getBoardName(), new Callable<MessageReply>()
                {
                    public MessageReply call()
                    {
                        boardRegistry.markCompleted(transferToBoardEndedMessage.getOperationNumber(), transferToBoardEndedMessage.getBoardName(), transferToBoardEndedMessage.getStepNumber());
                        return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getName()));
                    }
                });
            case DOWNLOAD_BOARD_CONTENTS:
                final BoardDownloadMessage downloadRequest = BoardDownloadMessage.getInstance(message.getPayload());

                return boardExecutor.submitTask(downloadRequest.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                    {
                        if (!boardRegistry.isDownloadLocked(downloadRequest.getBoardName()))
                        {
                            return new MessageReply(MessageReply.Type.ERROR, new BoardErrorStatusMessage(downloadRequest.getBoardName(), BoardErrorStatusMessage.Status.NOT_DOWNLOAD_LOCKED));
                        }

                        BulletinBoard board = boardRegistry.getBoard(downloadRequest.getBoardName());

                        PostedMessageBlock messages = board.removeMessages(new PostedMessageBlock.Builder(downloadRequest.getMaxNumberOfMessages()));

                        return new MessageReply(MessageReply.Type.OKAY, messages);
                    }
                });
            case DOWNLOAD_SHUFFLE_TRANSCRIPT:
                final TranscriptDownloadMessage transcriptDownloadMessage = TranscriptDownloadMessage.getInstance(message.getPayload());
                final BulletinBoard transitBoard = boardRegistry.getTransitBoard(transcriptDownloadMessage.getOperationNumber(), transcriptDownloadMessage.getStepNo());

                return boardExecutor.submitTask(transitBoard.getName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        String challengerKey = getChallengerKey(transcriptDownloadMessage);
                        IndexNumberGenerator challenger = challengers.get(challengerKey);
                        if (challenger == null)
                        {
                            if (TranscriptType.GENERAL == transcriptDownloadMessage.getType())
                            {
                                challenger = new SerialChallenger(transitBoard.transcriptSize(TranscriptType.GENERAL), transcriptDownloadMessage.getStepNo(), transcriptDownloadMessage.getSeed());
                            }
                            else
                            {
                                if (transcriptDownloadMessage.getSeed() != null)
                                {
                                    nodeContext.getEventNotifier().notify(EventNotifier.Level.INFO, "Challenge seed: " + new String(Hex.encode(transcriptDownloadMessage.getSeed())));
                                }
                                try
                                {
                                    challenger = (IndexNumberGenerator)witnessChallengerConstructor.newInstance(transitBoard.transcriptSize(transcriptDownloadMessage.getType()), transcriptDownloadMessage.getStepNo(), transcriptDownloadMessage.getSeed());
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
                    }
                });
            case DOWNLOAD_SHUFFLE_TRANSCRIPT_STEPS:
                final TranscriptQueryMessage transcriptQueryMessage = TranscriptQueryMessage.getInstance(message.getPayload());

                FutureTask<MessageReply> dstsTask = new FutureTask(new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        List<String> transitBoardNames = boardRegistry.getTransitBoardNames(transcriptQueryMessage.getOperationNumber());
                        int[] stepNos = new int[transitBoardNames.size()];
                        String boardName = "";

                        for (int i = 0; i != stepNos.length; i++)
                        {
                            String name = transitBoardNames.get(i);
                            boardName = name.substring(name.indexOf('.') + 1, name.lastIndexOf('.'));

                            stepNos[i] = Integer.parseInt(name.substring(name.lastIndexOf('.') + 1));
                        }

                        return new MessageReply(MessageReply.Type.OKAY, new TranscriptQueryResponse(queryCounter.incrementAndGet(), boardName, stepNos));
                    }
                });

                nodeContext.getScheduledExecutor().submit(dstsTask);

                return dstsTask;
            default:
                FutureTask<MessageReply> eTask = new FutureTask(new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Unknown command"));
                    }
                });

                nodeContext.getScheduledExecutor().submit(eTask);

                return eTask;
            }
        }
        else
        {
            switch (((ClientMessage)message).getType())
            {
            case UPLOAD_TO_BOARD:
                final BoardUploadMessage uploadMessage = BoardUploadMessage.getInstance(message.getPayload());

                return boardExecutor.submitTask(uploadMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                    {
                        if (boardRegistry.isLocked(uploadMessage.getBoardName()))
                        {
                            return new MessageReply(MessageReply.Type.ERROR, new BoardErrorStatusMessage(uploadMessage.getBoardName(), BoardErrorStatusMessage.Status.SUSPENDED));
                        }

                        byte[][] messages = uploadMessage.getData();

                        if (messages.length == 1)
                        {
                            boardRegistry.getBoard(uploadMessage.getBoardName()).postMessage(messages[0]);
                        }
                        else
                        {
                            boardRegistry.getBoard(uploadMessage.getBoardName()).postMessages(messages);
                        }

                        return new MessageReply(MessageReply.Type.OKAY, new DERUTF8String(nodeContext.getName()));
                    }
                });
            default:
                FutureTask<MessageReply> eTask = new FutureTask(new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Unknown command"));
                    }
                });

                nodeContext.getScheduledExecutor().submit(eTask);

                return eTask;
            }
        }
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
                    return new CapabilityMessage[]{BoardHostingService.this.getCapability()};
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

                        Constructor constructor = clazz.getConstructor(Integer.class, Integer.class, byte[].class);

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

                new TransformShuffleAndMoveTask(nodeContext, boardRegistry, getPeerConnection(startPandMmessage.getDestinationNode()), startPandMmessage).run();
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

                homeBoard.clear();

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

                boardRegistry.shuffleUnlock(transitBoardMessage.getBoardName());

            }
            catch (Exception e)
            {
                // TODO:
                e.printStackTrace();
            }
        }
    }
}
