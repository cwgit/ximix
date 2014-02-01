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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
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
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.Commitment;
import org.bouncycastle.crypto.commitments.GeneralHashCommitter;
import org.bouncycastle.crypto.digests.SHA512Digest;
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
import org.cryptoworkshop.ximix.common.asn1.message.CopyAndMoveMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CreateBoardMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ErrorMessage;
import org.cryptoworkshop.ximix.common.asn1.message.Message;
import org.cryptoworkshop.ximix.common.asn1.message.MessageCommitment;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.MessageType;
import org.cryptoworkshop.ximix.common.asn1.message.PermuteAndMoveMessage;
import org.cryptoworkshop.ximix.common.asn1.message.PostedData;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessage;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessageBlock;
import org.cryptoworkshop.ximix.common.asn1.message.SeedAndWitnessMessage;
import org.cryptoworkshop.ximix.common.asn1.message.SeedCommitmentMessage;
import org.cryptoworkshop.ximix.common.asn1.message.SeedMessage;
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptBlock;
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptDownloadMessage;
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptQueryMessage;
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptQueryResponse;
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptTransferMessage;
import org.cryptoworkshop.ximix.common.asn1.message.TransitBoardMessage;
import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.config.ConfigException;
import org.cryptoworkshop.ximix.common.config.ConfigObjectFactory;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.common.util.IndexNumberGenerator;
import org.cryptoworkshop.ximix.common.util.TranscriptType;
import org.cryptoworkshop.ximix.common.util.challenge.PairedChallenger;
import org.cryptoworkshop.ximix.common.util.challenge.SeededChallenger;
import org.cryptoworkshop.ximix.common.util.challenge.SerialChallenger;
import org.cryptoworkshop.ximix.node.mixnet.board.BulletinBoard;
import org.cryptoworkshop.ximix.node.mixnet.board.BulletinBoardRegistry;
import org.cryptoworkshop.ximix.node.mixnet.shuffle.CopyAndMoveTask;
import org.cryptoworkshop.ximix.node.mixnet.shuffle.TransformShuffleAndMoveTask;
import org.cryptoworkshop.ximix.node.mixnet.transform.Transform;
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
    private final Map<String, TranscriptGenerator> transcriptGenerators = new HashMap<>();
    private final Map<String, byte[][]> seedsAndWitnesses = new HashMap<>();
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

        this.boardExecutor = new BoardExecutor(decoupler, nodeContext.getExecutorService());

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
            case GENERATE_SEED:
                final SeedMessage seedMessage = SeedMessage.getInstance(message.getPayload());
                return boardExecutor.submitTask(seedMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        String seedKey = seedMessage.getBoardName() + "." + seedMessage.getOperationNumber();
                        if (seedsAndWitnesses.containsKey(seedKey))
                        {
                             return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Duplicate seed generation request for operation " + seedMessage.getOperationNumber()));
                        }
                                                                 // TODO: specify source of randomness
                        SecureRandom random = new SecureRandom();

                        byte[] seed = new byte[64];     // largest we can manage with SHA-512

                        random.nextBytes(seed);

                        GeneralHashCommitter sha512Committer = new GeneralHashCommitter(new SHA512Digest(), random);

                        Commitment commitment = sha512Committer.commit(seed);

                        seedsAndWitnesses.put(seedKey, new byte[][] { seed, commitment.getSecret() });

                        SeedCommitmentMessage seedCommitmentMessage = new SeedCommitmentMessage(seedMessage.getBoardName(), seedMessage.getOperationNumber(), commitment.getCommitment());

                        CMSSignedDataGenerator cmsGen = new CMSSignedDataGenerator();

                        KeyStore nodeCAStore = nodeContext.getNodeCAStore();
                        X509Certificate nodeCert = (X509Certificate)nodeCAStore.getCertificate("nodeCA");

                        cmsGen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").build("SHA256withECDSA", (PrivateKey)nodeCAStore.getKey("nodeCA", new char[0]), nodeCert));

                        cmsGen.addCertificate(new JcaX509CertificateHolder(nodeCert));

                        return new MessageReply(MessageReply.Type.OKAY, cmsGen.generate(new CMSProcessableByteArray(seedCommitmentMessage.getEncoded()), true).toASN1Structure());
                    }
                });
            case FETCH_SEED:
                final SeedMessage seedFetchMessage = SeedMessage.getInstance(message.getPayload());
                return boardExecutor.submitTask(seedFetchMessage.getBoardName(), new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        byte[][] seedAndWitness = seedsAndWitnesses.get(seedFetchMessage.getBoardName() + "." + seedFetchMessage.getOperationNumber());

                        return new MessageReply(MessageReply.Type.OKAY, new SeedAndWitnessMessage(seedAndWitness[0], seedAndWitness[1]));
                    }
                });
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
                final CopyAndMoveMessage startPandMmessage = CopyAndMoveMessage.getInstance(message.getPayload());

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

                        nodeContext.execute(new CopyAndMoveTask(nodeContext, boardRegistry, getPeerConnection(startPandMmessage.getDestinationNode()), startPandMmessage));

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

                return boardExecutor.submitBackupTask(backupBoardMessage.getBoardName(), new Callable<MessageReply>()
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

                return boardExecutor.submitBackupTask(uploadIndexedMessage.getBoardName(), new Callable<MessageReply>()
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
                        boolean isCopyBoard = isCopyBoard(transitBoard);
                        String challengerKey = getChallengerKey(transcriptDownloadMessage, isCopyBoard);

                        IndexNumberGenerator challenger = challengers.get(challengerKey);
                        if (challenger == null)
                        {
                            if (TranscriptType.GENERAL == transcriptDownloadMessage.getType())
                            {
                                challenger = new SerialChallenger(transitBoard.transcriptSize(TranscriptType.GENERAL), transcriptDownloadMessage.getStepNo(), transcriptDownloadMessage.getSeed());
                            }
                            else
                            {
                                SHA512Digest seedDigest = new SHA512Digest();
                                byte[]       challengeSeed = new byte[seedDigest.getDigestSize()];

                                if (transcriptDownloadMessage.getSeed() != null)
                                {
                                    byte[] originalSeed = transcriptDownloadMessage.getSeed();

                                    nodeContext.getEventNotifier().notify(EventNotifier.Level.INFO, "Original seed: " + new String(Hex.encode(originalSeed)));

                                    // we follow the formulation in "Randomized Partial Checking Revisited" where the seed is
                                    // modified by the step number, the one difference being that in our case this will only take
                                    // place at the start of a pairing, or on an individual step.
                                    seedDigest.update(originalSeed, 0, originalSeed.length);

                                    int stepNo = transcriptDownloadMessage.getStepNo();

                                    seedDigest.update((byte)(stepNo >>> 24));
                                    seedDigest.update((byte)(stepNo >>> 16));
                                    seedDigest.update((byte)(stepNo >>> 8));
                                    seedDigest.update((byte)stepNo);

                                    seedDigest.doFinal(challengeSeed, 0);
                                }

                                nodeContext.getEventNotifier().notify(EventNotifier.Level.INFO, "Challenge seed: " + transcriptDownloadMessage.getStepNo() + " " + new String(Hex.encode(challengeSeed)));

                                try
                                {
                                    if (isCopyBoard)
                                    {
                                        challenger = new SerialChallenger(transitBoard.transcriptSize(transcriptDownloadMessage.getType()), transcriptDownloadMessage.getStepNo(), challengeSeed);
                                    }
                                    else if (transcriptDownloadMessage.isWithPairing())
                                    {
                                        // TODO: maybe configure
                                        int chunkSize = 100;
                                        IndexNumberGenerator sourceGenerator = new SerialChallenger(transitBoard.size(), 0, null);
                                        int[] indexes = new int[transitBoard.size()];
                                        int count = 0;
                                        while (sourceGenerator.hasNext())
                                        {
                                            TranscriptBlock transcript = transitBoard.fetchTranscriptData(TranscriptType.WITNESSES, sourceGenerator, new TranscriptBlock.Builder(0, chunkSize));

                                            for (Enumeration en = transcript.getDetails().getObjects(); en.hasMoreElements();)
                                            {
                                                PostedData msg = PostedData.getInstance(en.nextElement());

                                                indexes[count++] = MessageCommitment.getInstance(msg.getData()).getNewIndex();
                                            }
                                        }

                                        challenger = new PairedChallenger(indexes, transcriptDownloadMessage.getStepNo(), (IndexNumberGenerator)witnessChallengerConstructor.newInstance(transitBoard.transcriptSize(transcriptDownloadMessage.getType()), transcriptDownloadMessage.getStepNo(), challengeSeed));
                                    }
                                    else
                                    {
                                        challenger = (IndexNumberGenerator)witnessChallengerConstructor.newInstance(transitBoard.transcriptSize(transcriptDownloadMessage.getType()), transcriptDownloadMessage.getStepNo(), challengeSeed);
                                    }
                                }
                                catch (Exception e)
                                {
                                    nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, e);

                                    return new MessageReply(MessageReply.Type.ERROR, new ErrorMessage("Unable to create challenger on " + nodeContext.getName()));
                                }
                            }
                            challengers.put(challengerKey, challenger);
                        }

                        if (challenger instanceof PairedChallenger)
                        {
                            ((PairedChallenger)challenger).setStepNo(transcriptDownloadMessage.getStepNo());
                        }

                        TranscriptBlock transcriptBlock = transitBoard.fetchTranscriptData(transcriptDownloadMessage.getType(), challenger, new TranscriptBlock.Builder(transcriptDownloadMessage.getStepNo(), transcriptDownloadMessage.getMaxNumberOfMessages()));

                        String generatorKey = getTranscriptGeneratorKey(transcriptDownloadMessage);
                        TranscriptGenerator transGen = transcriptGenerators.get(generatorKey);
                        if (transGen == null)
                        {
                            transGen = new TranscriptGenerator();

                            transcriptGenerators.put(generatorKey, transGen);
                        }

                        if (transcriptBlock.size() != 0)
                        {
                            for (Enumeration en = transcriptBlock.getDetails().getObjects(); en.hasMoreElements();)
                            {
                                transGen.writeFragment(((ASN1Object)en.nextElement()).getEncoded());
                            }

                            return new MessageReply(MessageReply.Type.OKAY, new TranscriptTransferMessage(transcriptBlock.getStepNo(), transGen.getFragment()));
                        }

                        if (transGen.hasData())
                        {
                            transGen.finish();
                            return new MessageReply(MessageReply.Type.OKAY, new TranscriptTransferMessage(transcriptBlock.getStepNo(), transGen.getFragment()));
                        }

                        // end of data
                        return new MessageReply(MessageReply.Type.OKAY, new TranscriptTransferMessage(transcriptBlock.getStepNo()));
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

                nodeContext.getExecutorService().submit(dstsTask);

                return dstsTask;
            default:
                FutureTask<MessageReply> eTask = new FutureTask(new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        return new MessageReply(MessageReply.Type.ERROR, new ErrorMessage("Unknown command"));
                    }
                });

                nodeContext.getExecutorService().submit(eTask);

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

                nodeContext.getExecutorService().submit(eTask);

                return eTask;
            }
        }
    }

    private String getChallengerKey(TranscriptDownloadMessage transcriptDownloadMessage, boolean isCopyBoard)
    {
        if (transcriptDownloadMessage.isWithPairing() && !isCopyBoard)
        {
            return Long.toString(transcriptDownloadMessage.getQueryID());
        }

        return transcriptDownloadMessage.getQueryID() + "." + transcriptDownloadMessage.getStepNo();
    }

    private String getTranscriptGeneratorKey(TranscriptDownloadMessage transcriptDownloadMessage)
    {
        return transcriptDownloadMessage.getQueryID() + "." + transcriptDownloadMessage.getStepNo();
    }

    private boolean isCopyBoard(BulletinBoard transitBoard)
    {
        IndexNumberGenerator sourceGenerator = new SerialChallenger(1, 0, null);
        while (sourceGenerator.hasNext())
        {
            TranscriptBlock transcript = transitBoard.fetchTranscriptData(TranscriptType.WITNESSES, sourceGenerator, new TranscriptBlock.Builder(0, 1));

            for (Enumeration en = transcript.getDetails().getObjects(); en.hasMoreElements();)
            {
                PostedData msg = PostedData.getInstance(en.nextElement());

                return MessageCommitment.getInstance(msg.getData()) == null;
            }
        }

        throw new IllegalStateException("sourceGenerator failed on copy step");
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
                public EventNotifier getEventNotifier()
                {
                    return nodeContext.getEventNotifier();
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
    }

    private class TranscriptGenerator
    {
        private CMSSignedDataStreamGenerator cmsGen = new CMSSignedDataStreamGenerator();
        private ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        private volatile OutputStream cmsOut;

        TranscriptGenerator()
            throws IOException
        {
        }

        public void writeFragment(byte[] fragment)
            throws Exception
        {
            if (cmsOut == null)
            {
                KeyStore nodeCAStore = nodeContext.getNodeCAStore();

                X509Certificate nodeCert = (X509Certificate)nodeCAStore.getCertificate("nodeCA");

                cmsGen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").build("SHA256withECDSA", (PrivateKey)nodeCAStore.getKey("nodeCA", new char[0]), nodeCert));

                cmsGen.addCertificate(new JcaX509CertificateHolder(nodeCert));

                cmsOut = cmsGen.open(bOut, true);
            }

            cmsOut.write(fragment);
        }

        public boolean hasData()
        {
            return cmsOut != null;
        }

        public void finish()
            throws IOException
        {
            cmsOut.close();
            cmsOut = null;
        }

        public byte[] getFragment()
        {
            byte[] fragment = bOut.toByteArray();

            bOut.reset();

            return fragment;
        }
    }
}
