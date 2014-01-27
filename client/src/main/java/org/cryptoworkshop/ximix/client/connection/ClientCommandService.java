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
package org.cryptoworkshop.ximix.client.connection;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.client.BoardCreationOptions;
import org.cryptoworkshop.ximix.client.CommandService;
import org.cryptoworkshop.ximix.client.DecryptionChallengeSpec;
import org.cryptoworkshop.ximix.client.DownloadOperationListener;
import org.cryptoworkshop.ximix.client.DownloadOptions;
import org.cryptoworkshop.ximix.client.DownloadShuffleResultOptions;
import org.cryptoworkshop.ximix.client.MessageChooser;
import org.cryptoworkshop.ximix.client.ShuffleOperationListener;
import org.cryptoworkshop.ximix.client.ShuffleOptions;
import org.cryptoworkshop.ximix.client.ShuffleTranscriptOptions;
import org.cryptoworkshop.ximix.client.ShuffleTranscriptsDownloadOperationListener;
import org.cryptoworkshop.ximix.common.asn1.PartialPublicKeyInfo;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequence;
import org.cryptoworkshop.ximix.common.asn1.board.PointSequence;
import org.cryptoworkshop.ximix.common.asn1.message.BoardDownloadMessage;
import org.cryptoworkshop.ximix.common.asn1.message.BoardMessage;
import org.cryptoworkshop.ximix.common.asn1.message.BoardStatusMessage;
import org.cryptoworkshop.ximix.common.asn1.message.BoardUploadMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ChallengeLogMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ClientMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CopyAndMoveMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CreateBoardMessage;
import org.cryptoworkshop.ximix.common.asn1.message.DecryptDataMessage;
import org.cryptoworkshop.ximix.common.asn1.message.DecryptShuffledBoardMessage;
import org.cryptoworkshop.ximix.common.asn1.message.DownloadShuffledBoardMessage;
import org.cryptoworkshop.ximix.common.asn1.message.FetchPartialPublicKeyMessage;
import org.cryptoworkshop.ximix.common.asn1.message.FetchPublicKeyMessage;
import org.cryptoworkshop.ximix.common.asn1.message.FileTransferMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.PermuteAndMoveMessage;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessage;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessageBlock;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessageDataBlock;
import org.cryptoworkshop.ximix.common.asn1.message.SeedAndWitnessMessage;
import org.cryptoworkshop.ximix.common.asn1.message.SeedMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ShareMessage;
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptDownloadMessage;
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptQueryMessage;
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptQueryResponse;
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptTransferMessage;
import org.cryptoworkshop.ximix.common.asn1.message.TransitBoardMessage;
import org.cryptoworkshop.ximix.common.crypto.threshold.LagrangeWeightCalculator;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.common.util.Operation;

/**
 * Internal implementation of the CommandService interface. This class creates the messages which are then sent down
 * the ServicesConnection.
 */
class ClientCommandService
    implements CommandService
{
    private final EventNotifier eventNotifier;

    private ExecutorService decouple = Executors.newSingleThreadExecutor();
    private ExecutorService executor = Executors.newCachedThreadPool();
    private AdminServicesConnection connection;

    private ConcurrentHashMap<String, FutureTask<String>> boardHostCache = new ConcurrentHashMap<>(); // TODO: maybe expire?

    public ClientCommandService(AdminServicesConnection connection, EventNotifier eventNotifier)
    {
        this.connection = connection;
        this.eventNotifier = eventNotifier;
    }

    static Set<String> toOrderedSet(String[] nodes)
    {
        Set<String> orderedSet = new TreeSet(new CaseInsensitiveComparator());

        for (String node : nodes)
        {
            orderedSet.add(node);
        }

        return Collections.unmodifiableSet(orderedSet);
    }

    @Override
    public void shutdown()
        throws ServiceConnectionException
    {
        decouple.shutdown();
        executor.shutdown();
        connection.close();
    }

    @Override
    public Operation<ShuffleOperationListener> doShuffleAndMove(String boardName, ShuffleOptions options, ShuffleOperationListener defaultListener, String... nodes)
        throws ServiceConnectionException
    {
        Operation<ShuffleOperationListener> op = new ShuffleOp(boardName, options, nodes);

        op.addListener(defaultListener);

        executor.execute((Runnable)op);

        return op;
    }

    @Override
    public Operation<DownloadOperationListener> downloadBoardContents(String boardName, DownloadOptions options, DownloadOperationListener defaultListener)
        throws ServiceConnectionException
    {
        Operation<DownloadOperationListener> op = new DownloadOp(Executors.newSingleThreadExecutor(), boardName, options);

        op.addListener(defaultListener);

        executor.execute((Runnable)op);

        return op;
    }

    @Override
    public Operation<DownloadOperationListener> downloadShuffleResult(String boardName, DownloadShuffleResultOptions options, Map<String, InputStream> seedCommitmentMap, Map<String, InputStream> seedAndWitnessesMap, Map<Integer, InputStream> generalTranscripts, Map<Integer, InputStream> witnessTranscripts, DownloadOperationListener defaultListener)
        throws ServiceConnectionException
    {
        Operation<DownloadOperationListener> op = new DownloadShuffleResultOp(Executors.newSingleThreadExecutor(), boardName, options, seedCommitmentMap, seedAndWitnessesMap, generalTranscripts, witnessTranscripts);

        op.addListener(defaultListener);

        executor.execute((Runnable)op);

        return op;
    }

    @Override
    public Map<String, byte[][]> downloadShuffleSeedsAndWitnesses(final String boardName, final long operationNumber, final String... nodes)
        throws ServiceConnectionException
    {
        FutureTask<Map<String, byte[][]>> task = new FutureTask<>(new Callable<Map<String, byte[][]>>()
        {
            @Override
            public Map<String, byte[][]> call()
                throws Exception
            {
                Map<String, byte[][]> seedsAndWitnesses = new HashMap<>();

                for (String node : nodes)
                {
                    MessageReply reply = connection.sendMessage(node, CommandMessage.Type.FETCH_SEED, new SeedMessage(boardName, operationNumber));

                    if (reply.getType() == MessageReply.Type.OKAY)
                    {
                        SeedAndWitnessMessage swMessage = SeedAndWitnessMessage.getInstance(reply.getPayload());

                        seedsAndWitnesses.put(node, new byte[][] { swMessage.getSeed(), swMessage.getWitness() });
                    }
                }

                return seedsAndWitnesses;
            }
        });

        executor.execute(task);

        try
        {
            return task.get();
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();

            eventNotifier.notify(EventNotifier.Level.ERROR, "Seed fetch task interrupted");
            throw new ServiceConnectionException("Seed fetch task interrupted");
        }
        catch (ExecutionException e)
        {
            eventNotifier.notify(EventNotifier.Level.ERROR, "Seed fetch task failed: " + e.getMessage(), e);
            throw new ServiceConnectionException("Seed fetch task failed: " + e.getMessage(), e);
        }
    }

    @Override
    public Operation<ShuffleTranscriptsDownloadOperationListener> downloadShuffleTranscripts(String boardName, long operationNumber, ShuffleTranscriptOptions transcriptOptions, ShuffleTranscriptsDownloadOperationListener defaultListener, String... nodes)
        throws ServiceConnectionException
    {
        // As downloading a shuffle transcript is a streaming operation it requires it's own decoupler otherwise everything blocks.
        Operation<ShuffleTranscriptsDownloadOperationListener> op = new DownloadShuffleTranscriptsOp(Executors.newSingleThreadExecutor(), boardName, operationNumber, transcriptOptions, nodes);

        op.addListener(defaultListener);

        executor.execute((Runnable)op);

        return op;
    }

    @Override
    public void createBoard(final String boardName, final BoardCreationOptions creationOptions)
        throws ServiceConnectionException
    {
        if (boardName.matches(".*[.:/].*$"))
        {
            throw new IllegalArgumentException("Board name cannot include '.' or ':'");
        }

        FutureTask<MessageReply> futureTask = new FutureTask<>(new Callable<MessageReply>()
        {
            @Override
            public MessageReply call()
                throws Exception
            {
                String hostName = creationOptions.getBoardHost();
                MessageReply reply;

                try
                {
                    reply = connection.sendMessage(hostName, CommandMessage.Type.BOARD_CREATE, new CreateBoardMessage(boardName, creationOptions.getBackUpHost()));

                    if (reply.getType() == MessageReply.Type.OKAY && creationOptions.getBackUpHost() != null)
                    {
                        reply = connection.sendMessage(creationOptions.getBackUpHost(), CommandMessage.Type.BACKUP_BOARD_CREATE, new BoardMessage(boardName));
                    }
                }
                catch (ServiceConnectionException e)
                {
                    eventNotifier.notify(EventNotifier.Level.ERROR, "Exception on board creation: " + e.getMessage(), e);
                    return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Exception on board creation: " + e.getMessage()));
                }

                return reply;
            }
        });

        executor.execute(futureTask);

        // TODO: sort out return values.
        try
        {
            MessageReply reply = futureTask.get();
        }
        catch (InterruptedException e)
        {
            eventNotifier.notify(EventNotifier.Level.ERROR, "InterrruptedException on board creation: " + e.getMessage(), e);
            Thread.currentThread().interrupt();
        }
        catch (Exception e)
        {
            eventNotifier.notify(EventNotifier.Level.ERROR, "Exception on board creation: " + e.getMessage(), e);
        }
    }

    @Override
    public Set<String> getNodeNames()
    {
        return Collections.unmodifiableSet(new HashSet<String>(connection.getActiveNodeNames()));
    }

    @Override
    public boolean isBoardExisting(final String boardName)
        throws ServiceConnectionException
    {
        FutureTask<MessageReply> futureTask = new FutureTask<>(new Callable<MessageReply>()
        {
            @Override
            public MessageReply call()
                throws Exception
            {

                MessageReply reply;

                try
                {
                    reply = connection.sendMessage(CommandMessage.Type.GET_BOARD_HOST, new BoardMessage(boardName));
                }
                catch (ServiceConnectionException e)
                {
                    eventNotifier.notify(EventNotifier.Level.ERROR, "Exception on isBoardExisting: " + e.getMessage(), e);
                    return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Exception on isBoardExisting: " + e.getMessage()));
                }

                return reply;
            }
        });

        executor.execute(futureTask);

        MessageReply reply = null;
        try
        {
            reply = futureTask.get();
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
        }
        catch (ExecutionException e)
        {
            throw new ServiceConnectionException("Unable to do isBoardExisting query: " + e.getMessage(), e);
        }

        return !(reply.getPayload() instanceof ASN1Null);
    }

    private String getHostName(final String boardName)
        throws ServiceConnectionException
    {
        if (!boardHostCache.containsKey(boardName))
        {
            FutureTask<String> futureTask = new FutureTask<>(new Callable<String>()
            {
                @Override
                public String call()
                    throws Exception
                {

                    MessageReply reply;

                    try
                    {
                        reply = connection.sendMessage(CommandMessage.Type.GET_BOARD_HOST, new BoardMessage(boardName));
                    }
                    catch (ServiceConnectionException e)
                    {
                        eventNotifier.notify(EventNotifier.Level.ERROR, "Exception on upload: " + e.getMessage(), e);
                        return "Exception on isBoardExisting: " + e.getMessage();
                    }

                    return DERUTF8String.getInstance(reply.getPayload()).getString();
                }
            });

            if (boardHostCache.putIfAbsent(boardName, futureTask) == null)
            {
                executor.submit(futureTask);
            }
        }

        try
        {
            return boardHostCache.get(boardName).get();
        }
        catch (InterruptedException e)
        {
            boardHostCache.remove(boardName);
            eventNotifier.notify(EventNotifier.Level.ERROR, "Exception on upload: " + e.getMessage(), e);
            throw new ServiceConnectionException(e.getMessage(), e);
        }
        catch (ExecutionException e)
        {
            boardHostCache.remove(boardName);
            eventNotifier.notify(EventNotifier.Level.ERROR, "Exception on upload: " + e.getMessage(), e);
            throw new ServiceConnectionException(e.getMessage(), e);
        }
    }

    @Override
    public void uploadMessage(String boardName, byte[] message)
        throws ServiceConnectionException
    {
        MessageReply reply = connection.sendMessage(getHostName(boardName), ClientMessage.Type.UPLOAD_TO_BOARD, new BoardUploadMessage(boardName, message));

        if (reply.getType() != MessageReply.Type.OKAY)
        {
            throw new ServiceConnectionException("message failed: " + DERUTF8String.getInstance(reply.getPayload()).getString());
        }
    }

    @Override
    public void uploadMessages(String boardName, byte[][] messages)
        throws ServiceConnectionException
    {
        MessageReply reply = connection.sendMessage(getHostName(boardName), ClientMessage.Type.UPLOAD_TO_BOARD, new BoardUploadMessage(boardName, messages));


        if (reply.getType() != MessageReply.Type.OKAY)
        {
            throw new ServiceConnectionException("message failed: " + DERUTF8String.getInstance(reply.getPayload()).getString());
        }
    }

    private static class CaseInsensitiveComparator
        implements Comparator<String>
    {
        @Override
        public int compare(String s1, String s2)
        {
            return s1.compareToIgnoreCase(s2);
        }
    }

    private class ShuffleOp
        extends Operation<ShuffleOperationListener>
        implements Runnable
    {
        private final String boardName;
        private final ShuffleOptions options;
        private final String[] nodes;

        public ShuffleOp(String boardName, ShuffleOptions options, String... nodes)
        {
            super(decouple, eventNotifier, ShuffleOperationListener.class);

            this.boardName = boardName;
            this.options = options;
            this.nodes = nodes;
        }

        public void run()
        {
            try
            {
                connection.sendMessage(CommandMessage.Type.BOARD_SHUFFLE_LOCK, new BoardMessage(boardName));

                Map<String, byte[]> commitmentMap = new HashMap<>();

                for (String node : nodes)
                {
                    if (commitmentMap.containsKey(node))
                    {
                        continue;
                    }

                    MessageReply seedReply = connection.sendMessage(node, CommandMessage.Type.GENERATE_SEED, new SeedMessage(boardName, this.getOperationNumber()));

                    if (seedReply.getType() == MessageReply.Type.OKAY)
                    {
                        ASN1Encodable msg = seedReply.getPayload();

                        commitmentMap.put(node, msg.toASN1Primitive().getEncoded());
                    }
                    else
                    {
                        notifier.failed(DERUTF8String.getInstance(seedReply.getPayload()).getString());
                        return;
                    }
                }

                notifier.commit(commitmentMap);

                // initial board state is copied to step 0 at start
                connection.sendMessage(nodes[0], CommandMessage.Type.INITIATE_INTRANSIT_BOARD, new TransitBoardMessage(this.getOperationNumber(), boardName, 0));

                MessageReply startRep = connection.sendMessage(CommandMessage.Type.START_SHUFFLE_AND_MOVE_BOARD_TO_NODE, new CopyAndMoveMessage(this.getOperationNumber(), boardName, 0, nodes[0]));
                if (startRep.getType() == MessageReply.Type.ERROR)
                {
                    notifier.failed(DERUTF8String.getInstance(startRep.getPayload()).getString());
                    return;
                }

                String boardHost = DERUTF8String.getInstance(startRep.getPayload()).getString();
                notifier.status("Starting  (" + nodes[0] + "/0)");
                for (int i = 0; i < nodes.length - 1; i++)
                {
                    waitForCompleteStatus(this.getOperationNumber(), nodes[i], i);

                    connection.sendMessage(nodes[i + 1], CommandMessage.Type.INITIATE_INTRANSIT_BOARD, new TransitBoardMessage(this.getOperationNumber(), boardName, i + 1));

                    MessageReply reply = connection.sendMessage(nodes[i], CommandMessage.Type.SHUFFLE_AND_MOVE_BOARD_TO_NODE, new PermuteAndMoveMessage(this.getOperationNumber(), boardName, i, options.getTransformName(), options.getKeyID(), nodes[i + 1]));
                    if (reply.getType() == MessageReply.Type.ERROR)
                    {
                        notifier.failed(DERUTF8String.getInstance(reply.getPayload()).getString());
                        return;
                    }

                    notifier.status("Shuffling (" + nodes[i + 1] + "/" + (i + 1) + ")");
                }

                waitForCompleteStatus(this.getOperationNumber(), nodes[nodes.length - 1], nodes.length - 1);

                connection.sendMessage(boardHost, CommandMessage.Type.INITIATE_INTRANSIT_BOARD, new TransitBoardMessage(this.getOperationNumber(), boardName, nodes.length));

                connection.sendMessage(nodes[nodes.length - 1], CommandMessage.Type.SHUFFLE_AND_MOVE_BOARD_TO_NODE, new PermuteAndMoveMessage(this.getOperationNumber(), boardName, nodes.length - 1, options.getTransformName(), options.getKeyID(), boardHost));

                waitForCompleteStatus(this.getOperationNumber(), boardHost, nodes.length);

                notifier.status("Returning (" + boardHost + "/" + nodes.length + ")");

                connection.sendMessage(boardHost, CommandMessage.Type.RETURN_TO_BOARD, new TransitBoardMessage(this.getOperationNumber(), boardName, nodes.length));

                waitForUnlockStatus(boardHost, boardName);

                notifier.completed();
            }
            catch (Exception e)
            {
                notifier.failed(e.toString());
            }
        }

        private void waitForCompleteStatus(long operationNumber, String curNode, int stepNumber)
            throws ServiceConnectionException
        {
            MessageReply tReply;
            do
            {
                try
                {
                    Thread.sleep(2000);  // TODO: configure?
                }
                catch (InterruptedException ex)
                {
                    Thread.currentThread().interrupt();
                }

                tReply = connection.sendMessage(curNode, CommandMessage.Type.FETCH_BOARD_STATUS, new TransitBoardMessage(operationNumber, boardName, stepNumber));
            }
            while (tReply.getType() == MessageReply.Type.OKAY && BoardStatusMessage.getInstance(tReply.getPayload()).getStatus() != BoardStatusMessage.Status.COMPLETE);
        }

        private void waitForUnlockStatus(String boardHost, String boardName)
            throws ServiceConnectionException
        {
            MessageReply tReply;
            do
            {
                try
                {
                    Thread.sleep(2000);  // TODO: configure?
                }
                catch (InterruptedException ex)
                {
                    Thread.currentThread().interrupt();
                }

                tReply = connection.sendMessage(boardHost, CommandMessage.Type.FETCH_BOARD_COMPLETION_STATUS, new BoardMessage(boardName));
            }
            while (tReply.getType() == MessageReply.Type.OKAY && BoardStatusMessage.getInstance(tReply.getPayload()).getStatus() != BoardStatusMessage.Status.COMPLETE);
        }

    }

    private class DownloadOp
        extends Operation<DownloadOperationListener>
        implements Runnable
    {
        private final ExecutorService decoupler;
        private final String boardName;
        private final DownloadOptions options;

        public DownloadOp(ExecutorService decoupler, String boardName, DownloadOptions options)
        {
            super(decoupler, eventNotifier, DownloadOperationListener.class);

            this.decoupler = decoupler;
            this.boardName = boardName;
            this.options = options;
        }

        public void run()
        {
            try
            {
                MessageReply reply = connection.sendMessage(CommandMessage.Type.BOARD_DOWNLOAD_LOCK, new BoardMessage(boardName));

                if (reply.getType() != MessageReply.Type.OKAY)
                {
                    notifier.failed(reply.getPayload().toString());
                    return;
                }

                String boardHost = DERUTF8String.getInstance(reply.getPayload()).getString();

                if (options.getKeyID() != null)
                {
                    String[] nodes = toOrderedSet(options.getNodesToUse()).toArray(new String[0]);
                    DecryptionChallengeSpec challengeSpec = options.getChallengeSpec();
                    Map<String, AsymmetricKeyParameter> keyMap = new HashMap<>();
                    MessageChooser proofMessageChooser = null;
                    OutputStream proofLogStream = null;

                    if (challengeSpec != null)
                    {
                        for (String node : nodes)
                        {
                            reply = connection.sendMessage(node, CommandMessage.Type.FETCH_PARTIAL_PUBLIC_KEY, new FetchPartialPublicKeyMessage(node, options.getKeyID()));

                            if (reply.getType() != MessageReply.Type.OKAY)
                            {
                                throw new ServiceConnectionException("message failed");
                            }

                            try
                            {
                                PartialPublicKeyInfo partialPublicKeyInfo = PartialPublicKeyInfo.getInstance(reply.getPayload());

                                keyMap.put(node, PublicKeyFactory.createKey(partialPublicKeyInfo.getPartialKeyInfo()));
                            }
                            catch (Exception e)
                            {
                                throw new ServiceConnectionException("Malformed public key response.");
                            }
                        }

                        proofMessageChooser = challengeSpec.getChooser();
                        proofLogStream = challengeSpec.getLogStream();
                    }

                    for (;;)
                    {
                        reply = connection.sendMessage(boardHost, CommandMessage.Type.DOWNLOAD_BOARD_CONTENTS, new BoardDownloadMessage(boardName, 20)); // TODO: configure

                        PostedMessageBlock messageBlock = PostedMessageBlock.getInstance(reply.getPayload());

                        if (messageBlock.size() == 0)
                        {
                            break;
                        }

                        PostedMessageDataBlock.Builder messageDataBuilder = new PostedMessageDataBlock.Builder(messageBlock.size());

                        for (PostedMessage postedMessage : messageBlock.getMessages())
                        {
                            messageDataBuilder.add(postedMessage.getMessage());
                        }

                        PostedMessageDataBlock data = messageDataBuilder.build();

                        MessageReply[] partialDecryptResponses = new MessageReply[options.getThreshold()];
                        String[] nodesUsed = new String[options.getThreshold()];

                        // TODO: deal with drop outs
                        int count = 0;
                        while (count != options.getThreshold())
                        {
                            partialDecryptResponses[count] = connection.sendMessage(nodes[count], CommandMessage.Type.PARTIAL_DECRYPT, new DecryptDataMessage(options.getKeyID(), data.getMessages()));
                            if (partialDecryptResponses[count].getType() == MessageReply.Type.OKAY)
                            {
                                nodesUsed[count] = nodes[count];
                                count++;
                            }
                            else
                            {
                                // TODO: maybe log
                                partialDecryptResponses[count] = null;
                            }
                        }

                        MessageReply keyReply = connection.sendMessage(ClientMessage.Type.FETCH_PUBLIC_KEY, new FetchPublicKeyMessage(options.getKeyID()));

                        SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfo.getInstance(keyReply.getPayload());

                        ECDomainParameters domainParams = ((ECPublicKeyParameters)PublicKeyFactory.createKey(pubKeyInfo)).getParameters();

                        ShareMessage[] shareMessages = new ShareMessage[options.getThreshold()];
                        int maxSequenceNo = 0;

                        for (int i = 0; i != shareMessages.length; i++)
                        {
                            shareMessages[i] = ShareMessage.getInstance(partialDecryptResponses[i].getPayload());
                            if (maxSequenceNo < shareMessages[i].getSequenceNo())
                            {
                                maxSequenceNo = shareMessages[i].getSequenceNo();
                            }
                        }

                        // weighting
                        List<byte[]>[] partialDecrypts = new List[maxSequenceNo + 1];

                        for (int i = 0; i != shareMessages.length; i++)
                        {
                            ShareMessage shareMsg = shareMessages[i];

                            partialDecrypts[shareMsg.getSequenceNo()] = PostedMessageDataBlock.getInstance(shareMsg.getShareData()).getMessages();
                        }

                        //
                        // we don't need to know how many peers, just the maximum index (maxSequenceNo + 1) of the one available
                        //
                        LagrangeWeightCalculator calculator = new LagrangeWeightCalculator(maxSequenceNo + 1, domainParams.getN());

                        BigInteger[] weights = calculator.computeWeights(partialDecrypts);

                        int baseIndex = 0;
                        for (int i = 0; i != partialDecrypts.length; i++)
                        {
                            if (partialDecrypts[i] != null)
                            {
                                baseIndex = i;
                                break;
                            }
                        }

                        List<byte[]> baseMessageBlock = partialDecrypts[baseIndex];
                        BigInteger baseWeight = weights[baseIndex];
                        List<PostedMessage> postedMessages = messageBlock.getMessages();

                        for (int messageIndex = 0; messageIndex != baseMessageBlock.size(); messageIndex++)
                        {
                            ECPoint[] fulls = reassemblePoints(messageIndex, domainParams, partialDecrypts, weights, baseIndex, baseMessageBlock, baseWeight);

                            int index = postedMessages.get(messageIndex).getIndex();

                            if (proofMessageChooser != null)
                            {
                                if (proofMessageChooser.chooseMessage(index))
                                {
                                    issueChallenge(proofLogStream, index, nodesUsed, keyMap, fulls);
                                }
                            }

                            notifier.messageDownloaded(index, new PointSequence(fulls).getEncoded());
                        }
                    }
                }
                else
                {
                    // assume plain text
                    for (; ; )
                    {
                        reply = connection.sendMessage(CommandMessage.Type.DOWNLOAD_BOARD_CONTENTS, new BoardDownloadMessage(boardName, 10));

                        if (reply.getType() == MessageReply.Type.OKAY)
                        {
                            PostedMessageBlock messageBlock = PostedMessageBlock.getInstance(reply.getPayload());

                            if (messageBlock.size() == 0)
                            {
                                break;
                            }

                            for (PostedMessage posted : messageBlock.getMessages())
                            {
                                notifier.messageDownloaded(posted.getIndex(), posted.getMessage());
                            }
                        }
                        else
                        {
                            notifier.failed("Failed: " + reply.getPayload().toString());
                            return;
                        }
                    }
                }

                connection.sendMessage(CommandMessage.Type.BOARD_DOWNLOAD_UNLOCK, new BoardMessage(boardName));

                notifier.completed();
            }
            catch (Exception e)
            {
                eventNotifier.notify(EventNotifier.Level.ERROR, "Exception in download: " + e.getMessage(), e);
                notifier.failed(e.toString());
            }
            finally
            {
                decoupler.shutdown();
            }
        }

        //
        // generate and log a zero knowledge proof.
        //
        // "A Secure and Optimally Efficient Multi-Authority Election Scheme"
        // R. Cramer, R. Gennaro, B. Schoenmakers, CGS Journal, October, 1997.
        // Section 2.6
        //
        private void issueChallenge(OutputStream proofLogStream, int messageIndex, String[] nodes, Map<String, AsymmetricKeyParameter> keyMap, ECPoint[] sourceMessage)
            throws IOException, ServiceConnectionException
        {
            SHA256Digest sha256 = new SHA256Digest();
            Map<String, SubjectPublicKeyInfo> keyInfoMap = new HashMap<>();

            //
            // compute the multiplier m
            //
            for (int i = 0; i != sourceMessage.length; i++)
            {
                byte[] encoded = sourceMessage[i].getEncoded();

                sha256.update(encoded, 0, encoded.length);
            }

            for (String node : nodes)
            {
                AsymmetricKeyParameter key = keyMap.get(node);

                SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key);

                keyInfoMap.put(node, keyInfo);

                byte[] encoded = keyInfo.getEncoded();

                sha256.update(encoded, 0, encoded.length);
            }

            byte[] mEnc = new byte[sha256.getDigestSize()];

            sha256.doFinal(mEnc, 0);

            BigInteger m = new BigInteger(1, mEnc);

            ECPoint[] challengeMessage = new ECPoint[sourceMessage.length];

            for (int i = 0; i != sourceMessage.length; i++)
            {
                challengeMessage[i] = sourceMessage[i].multiply(m);
            }

            ECElGamalEncryptor ecEnc = new ECElGamalEncryptor();

            for (String node : nodes)
            {
                ECPublicKeyParameters key = (ECPublicKeyParameters)keyMap.get(node);

                ecEnc.init(key);

                ECPair[] encChallengeMessage = new ECPair[sourceMessage.length];

                for (int i = 0; i != challengeMessage.length; i++)
                {
                    encChallengeMessage[i] = ecEnc.encrypt(challengeMessage[i]);
                }

                List<byte[]> message = Collections.singletonList(new PairSequence(encChallengeMessage).getEncoded());

                MessageReply reply = connection.sendMessage(node, CommandMessage.Type.PARTIAL_DECRYPT, new DecryptDataMessage(options.getKeyID(), message));

                if (reply.getType() == MessageReply.Type.OKAY)
                {
                    ShareMessage shareMessage = ShareMessage.getInstance(reply.getPayload());
                    List<byte[]> dataBlock = PostedMessageDataBlock.getInstance(shareMessage.getShareData()).getMessages();
                    PairSequence ps = PairSequence.getInstance(key.getParameters().getCurve(), dataBlock.get(0));

                    ECPair[] decrypts = ps.getECPairs();
                    ECPoint[] challengeResult = new ECPoint[decrypts.length];

                    for (int i = 0; i != decrypts.length; i++)
                    {
                        challengeResult[i] = decrypts[i].getX();
                    }

                    for (int i = 0; i != decrypts.length; i++)
                    {
                        challengeResult[i] = decrypts[i].getY().add(challengeResult[i].negate());
                    }

                    if (Arrays.equals(challengeMessage, challengeResult))
                    {
                        proofLogStream.write(new ChallengeLogMessage(messageIndex, shareMessage.getSequenceNo(), true, m, keyInfoMap.get(node), sourceMessage, challengeResult).getEncoded());
                        eventNotifier.notify(EventNotifier.Level.INFO, "Challenge for message " + messageIndex + " for node " + node + " passed.");
                    }
                    else
                    {
                        proofLogStream.write(new ChallengeLogMessage(messageIndex, shareMessage.getSequenceNo(), false, m, keyInfoMap.get(node), sourceMessage, challengeResult).getEncoded());
                        eventNotifier.notify(EventNotifier.Level.ERROR, "Challenge for message " + messageIndex + " for node " + node + " failed!");
                    }
                }
                else
                {
                    eventNotifier.notify(EventNotifier.Level.ERROR, "Challenge message rejected");
                }
            }
        }
    }

    private class DownloadShuffleResultOp
        extends Operation<DownloadOperationListener>
        implements Runnable
    {
        private final ExecutorService decoupler;
        private final String boardName;
        private final DownloadShuffleResultOptions options;
        private final Map<String, InputStream> seedCommitmentMap;
        private final Map<String, InputStream> seedAndWitnessesMap;
        private final Map<Integer, InputStream> generalTranscripts;
        private final Map<Integer, InputStream> witnessTranscripts;

        public DownloadShuffleResultOp(ExecutorService decoupler, String boardName, DownloadShuffleResultOptions options, Map<String, InputStream> seedCommitmentMap, Map<String, InputStream> seedAndWitnessesMap, Map<Integer, InputStream> generalTranscripts, Map<Integer, InputStream> witnessTranscripts)
        {
            super(decoupler, eventNotifier, DownloadOperationListener.class);

            this.decoupler = decoupler;
            this.boardName = boardName;
            this.options = options;
            this.seedCommitmentMap = seedCommitmentMap;
            this.seedAndWitnessesMap = seedAndWitnessesMap;
            this.generalTranscripts = generalTranscripts;
            this.witnessTranscripts = witnessTranscripts;
        }

        public void run()
        {
            String[] nodes = toOrderedSet(options.getNodesToUse()).toArray(new String[0]);

            //
            // upload the transcripts
            //
            if (!uploadMaps(nodes, seedCommitmentMap, ".sc"))
            {
                return;
            }

            if (!uploadMaps(nodes, seedAndWitnessesMap, ".svw"))
            {
                return;
            }

            if (!uploadTranscript(nodes, generalTranscripts, ".gtr"))
            {
                return;
            }

            if (!uploadTranscript(nodes, witnessTranscripts, ".wtr"))
            {
                return;
            }

            //
            // initialise the decryption process
            //
            for (String node : nodes)
            {
                try
                {
                    MessageReply reply = connection.sendMessage(node, CommandMessage.Type.SETUP_PARTIAL_DECRYPT, new DecryptShuffledBoardMessage(options.getKeyID(), boardName, options.isPairingEnabled()));
                    if (!reply.getType().equals(MessageReply.Type.OKAY))
                    {
                        notifier.failed(node + " reply " + DERUTF8String.getInstance(reply.getPayload()).getString());
                        return;
                    }
                }
                catch (Exception e)
                {
                    notifier.failed(e.toString());
                    return;
                }
            }

            int boardIndex = 0;

            ECDomainParameters domainParams;

            try
            {
                MessageReply keyReply = connection.sendMessage(ClientMessage.Type.FETCH_PUBLIC_KEY, new FetchPublicKeyMessage(options.getKeyID()));

                SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfo.getInstance(keyReply.getPayload());

                domainParams = ((ECPublicKeyParameters)PublicKeyFactory.createKey(pubKeyInfo)).getParameters();
            }
            catch (Exception e)
            {
                notifier.failed(e.toString());
                return;
            }

            for (;;)
            {
                MessageReply[] partialDecryptResponses = new MessageReply[options.getThreshold()];
                String[] nodesUsed = new String[options.getThreshold()];

                try
                {
                    // TODO: deal with drop outs - in this case it's tricky, backend code will need to take into account a node
                    // might be asked to take over half way through.
                    int count = 0;
                    while (count != options.getThreshold())
                    {
                        partialDecryptResponses[count] = connection.sendMessage(nodes[count], CommandMessage.Type.DOWNLOAD_PARTIAL_DECRYPTS, new DownloadShuffledBoardMessage(options.getKeyID(), boardName, 100)); // TODO: configure;
                        if (partialDecryptResponses[count].getType() == MessageReply.Type.OKAY)
                        {
                            nodesUsed[count] = nodes[count];
                            count++;
                        }
                        else
                        {
                            // TODO: maybe log
                            partialDecryptResponses[count] = null;
                        }
                    }


                    int pdIndex = 0;
                    while (partialDecryptResponses[pdIndex] == null)
                    {
                        pdIndex++;
                    }

                    PostedMessageDataBlock baseBlock = PostedMessageDataBlock.getInstance(ShareMessage.getInstance(partialDecryptResponses[pdIndex].getPayload()).getShareData());
                    if (baseBlock.size() == 0)
                    {
                        break;
                    }

                    ShareMessage[] shareMessages = new ShareMessage[options.getThreshold()];
                    int maxSequenceNo = 0;

                    for (int i = 0; i != shareMessages.length; i++)
                    {
                        shareMessages[i] = ShareMessage.getInstance(partialDecryptResponses[pdIndex++].getPayload());
                        if (maxSequenceNo < shareMessages[i].getSequenceNo())
                        {
                            maxSequenceNo = shareMessages[i].getSequenceNo();
                        }
                    }

                    // weighting
                    List<byte[]>[] partialDecrypts = new List[maxSequenceNo + 1];

                    for (int i = 0; i != shareMessages.length; i++)
                    {
                        ShareMessage shareMsg = shareMessages[i];

                        partialDecrypts[shareMsg.getSequenceNo()] = PostedMessageDataBlock.getInstance(shareMsg.getShareData()).getMessages();
                    }

                    //
                    // we don't need to know how many peers, just the maximum index (maxSequenceNo + 1) of the one available
                    //
                    LagrangeWeightCalculator calculator = new LagrangeWeightCalculator(maxSequenceNo + 1, domainParams.getN());

                    BigInteger[] weights = calculator.computeWeights(partialDecrypts);

                    int baseIndex = 0;
                    for (int i = 0; i != partialDecrypts.length; i++)
                    {
                        if (partialDecrypts[i] != null)
                        {
                            baseIndex = i;
                            break;
                        }
                    }

                    List<byte[]> baseMessageBlock = partialDecrypts[baseIndex];
                    BigInteger baseWeight = weights[baseIndex];

                    for (int messageIndex = 0; messageIndex != baseBlock.size(); messageIndex++)
                    {
                        ECPoint[] fulls = reassemblePoints(messageIndex, domainParams, partialDecrypts, weights, baseIndex, baseMessageBlock, baseWeight);

                        notifier.messageDownloaded(boardIndex++, new PointSequence(fulls).getEncoded());
                    }
                }
                catch (Exception e)
                {
                    notifier.failed(e.toString());
                }
            }

            notifier.completed();

            decoupler.shutdown();
        }

        private boolean uploadMaps(String[] nodes, Map<String, InputStream> transcriptMap, String suffix)
        {
            for (String key : transcriptMap.keySet())
            {
                try
                {
                    if (!uploadStream(nodes, boardName + "." + key + suffix, transcriptMap.get(key)))
                    {
                        return false;
                    }
                }
                catch (Exception e)
                {
                    notifier.failed(e.toString());
                    return false;
                }
            }

            return true;
        }

        private boolean uploadTranscript(String[] nodes, Map<Integer, InputStream> transcriptMap, String suffix)
        {
            for (Integer key : transcriptMap.keySet())
            {
                try
                {
                    if (!uploadStream(nodes, boardName + "." + key + suffix, transcriptMap.get(key)))
                    {
                        return false;
                    }
                }
                catch (Exception e)
                {
                    notifier.failed(e.toString());
                    return false;
                }
            }
            return true;
        }

        private boolean uploadStream(String[] nodes, String targetName, InputStream input)
            throws IOException, ServiceConnectionException
        {
            int chunkSize = 10240; // TODO: make configurable
            InputStream fIn = new BufferedInputStream(input, chunkSize);
            byte[] chunk = new byte[chunkSize];

            int in;
            while ((in = fIn.read(chunk)) >= 0)
            {
                if (in < chunkSize)
                {
                    byte[] tmp = new byte[in];
                    System.arraycopy(chunk, 0, tmp, 0, tmp.length);
                    chunk = tmp;
                }

                FileTransferMessage trfMessage = new FileTransferMessage(targetName, chunk);
                for (String node : nodes)
                {
                    MessageReply reply = connection.sendMessage(node, CommandMessage.Type.FILE_UPLOAD, trfMessage);
                    if (!reply.getType().equals(MessageReply.Type.OKAY))
                    {
                        notifier.failed(node + " reply " + DERUTF8String.getInstance(reply.getPayload()).getString());
                        return false;
                    }
                }
            }

            FileTransferMessage endMessage = new FileTransferMessage(targetName);
            for (String node : nodes)
            {
                MessageReply reply = connection.sendMessage(node, CommandMessage.Type.FILE_UPLOAD, endMessage);
                if (!reply.getType().equals(MessageReply.Type.OKAY))
                {
                    notifier.failed(node + " reply " + DERUTF8String.getInstance(reply.getPayload()).getString());
                    return false;
                }
            }
            return true;
        }
    }

    private ECPoint[] reassemblePoints(int messageIndex, ECDomainParameters domainParams, List<byte[]>[] partialDecrypts, BigInteger[] weights, int baseIndex, List<byte[]> baseMessageBlock, BigInteger baseWeight)
    {
        PairSequence ps = PairSequence.getInstance(domainParams.getCurve(), baseMessageBlock.get(messageIndex));
        ECPoint[] weightedDecryptions = new ECPoint[ps.size()];
        ECPoint[] fulls = new ECPoint[ps.size()];

        ECPair[] partials = ps.getECPairs();
        for (int i = 0; i != weightedDecryptions.length; i++)
        {
            weightedDecryptions[i] = partials[i].getX().multiply(baseWeight);
        }

        for (int wIndex = baseIndex + 1; wIndex < weights.length; wIndex++)
        {
            if (weights[wIndex] != null)
            {
                ECPair[] nPartials = PairSequence.getInstance(domainParams.getCurve(), partialDecrypts[wIndex].get(messageIndex)).getECPairs();
                for (int i = 0; i != weightedDecryptions.length; i++)
                {
                    weightedDecryptions[i] = weightedDecryptions[i].add(nPartials[i].getX().multiply(weights[wIndex]));
                }
            }
        }

        for (int i = 0; i != weightedDecryptions.length; i++)
        {
            fulls[i] = partials[i].getY().add(weightedDecryptions[i].negate());
        }

        return fulls;
    }

    private class DownloadShuffleTranscriptsOp
        extends Operation<ShuffleTranscriptsDownloadOperationListener>
        implements Runnable
    {
        private final String boardName;
        private final long operationOfInterestNumber;
        private final ShuffleTranscriptOptions transcriptOptions;
        private final String[] nodes;
        private final ExecutorService decoupler;

        public DownloadShuffleTranscriptsOp(ExecutorService decoupler, String boardName, long operationOfInterestNumber, ShuffleTranscriptOptions transcriptOptions, String... nodes)
        {
            super(decoupler, eventNotifier, ShuffleTranscriptsDownloadOperationListener.class);

            this.decoupler = decoupler;
            this.boardName = boardName;
            this.operationOfInterestNumber = operationOfInterestNumber;
            this.transcriptOptions = transcriptOptions;
            this.nodes = nodes;
        }

        public void run()
        {
            try
            {
                for (String node : nodes)
                {
                    processNode(node);
                }

                //
                // check we have included the board host
                //
                boolean notFound = true;

                MessageReply startRep = connection.sendMessage(CommandMessage.Type.GET_BOARD_HOST, new BoardMessage(boardName));
                String boardHost = DERUTF8String.getInstance(startRep.getPayload()).getString();

                for (int i = 0; i != nodes.length; i++)
                {
                    if (nodes[i].equals(boardHost))
                    {
                        notFound = false;
                        break;
                    }
                }

                if (notFound)
                {
                    processNode(boardHost);
                }

                notifier.completed();
            }
            catch (Exception e)
            {
                notifier.failed(e.toString());
            }

            decoupler.shutdown();
        }

        private void processNode(String node)
            throws ServiceConnectionException, IOException
        {
            MessageReply reply = connection.sendMessage(node, CommandMessage.Type.DOWNLOAD_SHUFFLE_TRANSCRIPT_STEPS, new TranscriptQueryMessage(operationOfInterestNumber));

            TranscriptQueryResponse response = TranscriptQueryResponse.getInstance(reply.getPayload());

            String opBoardName = response.getBoardName();

            if (!boardName.equals(opBoardName))
            {
                throw new IllegalStateException("node reports incorrect board name");
            }

            long queryID = response.getQueryID();

            int[] stepNos = response.stepNos();

            // need to make sure these are in a specific order for challenge verification to work.
            Arrays.sort(stepNos);

            for (int stepNo : stepNos)
            {
                PipedOutputStream pOut = null;

                for (; ; )
                {
                    reply = connection.sendMessage(node, CommandMessage.Type.DOWNLOAD_SHUFFLE_TRANSCRIPT, new TranscriptDownloadMessage(queryID, operationOfInterestNumber, stepNo, transcriptOptions.getTranscriptType(), transcriptOptions.getChunkSize(), transcriptOptions.isPairingEnabled(), transcriptOptions.getSeedValue()));

                    TranscriptTransferMessage transcriptBlock = TranscriptTransferMessage.getInstance(reply.getPayload());

                    if (transcriptBlock.isEndOfTransfer())
                    {
                        break;
                    }

                    if (pOut == null)
                    {
                        pOut = new PipedOutputStream();
                        PipedInputStream pIn = new PipedInputStream(pOut);

                        notifier.shuffleTranscriptArrived(operationOfInterestNumber, transcriptBlock.getStepNo(), pIn);
                    }

                    pOut.write(transcriptBlock.getChunk());
                }

                if (pOut != null)
                {
                    pOut.close();
                }
            }
        }
    }
}
