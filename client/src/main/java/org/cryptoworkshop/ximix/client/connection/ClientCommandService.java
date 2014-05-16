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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
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
import java.util.concurrent.RunnableFuture;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.io.TeeInputStream;
import org.cryptoworkshop.ximix.client.BoardCreationOptions;
import org.cryptoworkshop.ximix.client.CommandService;
import org.cryptoworkshop.ximix.client.DownloadOperationListener;
import org.cryptoworkshop.ximix.client.DownloadOptions;
import org.cryptoworkshop.ximix.client.DownloadShuffleResultOptions;
import org.cryptoworkshop.ximix.client.ShuffleOperationListener;
import org.cryptoworkshop.ximix.client.ShuffleOptions;
import org.cryptoworkshop.ximix.client.ShuffleStatus;
import org.cryptoworkshop.ximix.client.ShuffleTranscriptOptions;
import org.cryptoworkshop.ximix.client.ShuffleTranscriptsDownloadOperationListener;
import org.cryptoworkshop.ximix.common.asn1.PartialPublicKeyInfo;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequence;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequenceWithProofs;
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
import org.cryptoworkshop.ximix.common.asn1.message.ErrorMessage;
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
import org.cryptoworkshop.ximix.common.crypto.ECDecryptionProof;
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

    public ClientCommandService(AdminServicesConnection connection)
    {
        this.connection = connection;
        this.eventNotifier = connection.getEventNotifier();
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
        connection.shutdown();
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
                    else
                    {
                        eventNotifier.notify(EventNotifier.Level.ERROR, "Unable to get seed and witness from " + node + ": " + reply.interpretPayloadAsError());
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
                        if (reply.getType() != MessageReply.Type.OKAY)
                        {
                            eventNotifier.notify(EventNotifier.Level.ERROR, "Error on backup board creation: " + reply.interpretPayloadAsError());
                        }
                    }
                }
                catch (ServiceConnectionException e)
                {
                    eventNotifier.notify(EventNotifier.Level.ERROR, "Exception on board creation: " + e.getMessage(), e);

                    return new MessageReply(MessageReply.Type.ERROR, new ErrorMessage("Exception on board creation: " + e.getMessage()));
                }

                return reply;
            }
        });

        executor.execute(futureTask);

        try
        {
            MessageReply reply = futureTask.get();
            if (reply.getType() != MessageReply.Type.OKAY)
            {
                throw new ServiceConnectionException("Unable to create board: " + reply.interpretPayloadAsError());
            }
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

                    return new MessageReply(MessageReply.Type.ERROR, new ErrorMessage("Exception on isBoardExisting: " + e.getMessage()));
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

        return reply != null && !(reply.getPayload() instanceof ASN1Null);
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

                        return "Exception on GET_BOARD_HOST: " + e.getMessage();
                    }

                    return (reply.getType() == MessageReply.Type.OKAY) ? DERUTF8String.getInstance(reply.getPayload()).getString() : reply.interpretPayloadAsError();
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
            eventNotifier.notify(EventNotifier.Level.ERROR, "Exception on getHostName(): " + e.getMessage(), e);
            Thread.currentThread().interrupt();
            throw new ServiceConnectionException(e.getMessage(), e);
        }
        catch (ExecutionException e)
        {
            boardHostCache.remove(boardName);
            eventNotifier.notify(EventNotifier.Level.ERROR, "Exception on getHostName(): " + e.getMessage(), e);
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
            throw new ServiceConnectionException("message failed: " + reply.interpretPayloadAsError());
        }
    }

    @Override
    public void uploadMessages(String boardName, byte[][] messages)
        throws ServiceConnectionException
    {
        MessageReply reply = connection.sendMessage(getHostName(boardName), ClientMessage.Type.UPLOAD_TO_BOARD, new BoardUploadMessage(boardName, messages));


        if (reply.getType() != MessageReply.Type.OKAY)
        {
            throw new ServiceConnectionException("message failed: " + reply.interpretPayloadAsError());
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
                MessageReply reply = connection.sendMessage(CommandMessage.Type.BOARD_SHUFFLE_LOCK, new BoardMessage(boardName));
                if (reply.getType() != MessageReply.Type.OKAY)
                {
                    notifier.failed(new ShuffleStatus(reply.interpretPayloadAsError(), "", null));
                    return;
                }

                String boardHost = DERUTF8String.getInstance(reply.getPayload()).getString();

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
                        notifier.failed(new ShuffleStatus(seedReply.interpretPayloadAsError(), node, null));
                        return;
                    }
                }

                notifier.commit(commitmentMap);

                // initial board state is copied to step 0 at start
                reply = connection.sendMessage(nodes[0], CommandMessage.Type.INITIATE_INTRANSIT_BOARD, new TransitBoardMessage(this.getOperationNumber(), boardName, 0));
                if (reply.getType() != MessageReply.Type.OKAY)
                {
                    notifier.failed(new ShuffleStatus(reply.interpretPayloadAsError(), nodes[0], null));
                    return;
                }

                reply = connection.sendMessage(boardHost, CommandMessage.Type.START_SHUFFLE_AND_MOVE_BOARD_TO_NODE, new CopyAndMoveMessage(this.getOperationNumber(), boardName, 0, nodes[0]));
                if (reply.getType() != MessageReply.Type.OKAY)
                {
                    notifier.failed(new ShuffleStatus(reply.interpretPayloadAsError(), boardHost, null));
                    return;
                }


                notifier.status(new ShuffleStatus("Starting  (" + nodes[0] + "/0)", nodes[0], 0));
                for (int i = 0; i < nodes.length - 1; i++)
                {
                    waitForCompleteStatus(this.getOperationNumber(), nodes[i], i);

                    reply = connection.sendMessage(nodes[i + 1], CommandMessage.Type.INITIATE_INTRANSIT_BOARD, new TransitBoardMessage(this.getOperationNumber(), boardName, i + 1));
                    if (reply.getType() != MessageReply.Type.OKAY)
                    {
                        notifier.failed(new ShuffleStatus(reply.interpretPayloadAsError(), nodes[i + 1], null));
                        return;
                    }

                    reply = connection.sendMessage(nodes[i], CommandMessage.Type.SHUFFLE_AND_MOVE_BOARD_TO_NODE, new PermuteAndMoveMessage(this.getOperationNumber(), boardName, i, options.getTransformName(), options.getKeyID(), nodes[i + 1]));
                    if (reply.getType() != MessageReply.Type.OKAY)
                    {
                        notifier.failed(new ShuffleStatus(reply.interpretPayloadAsError(), nodes[i + 1], null));
                        return;
                    }

                    notifier.status(new ShuffleStatus("Shuffling (" + nodes[i + 1] + "/" + (i + 1) + ")", nodes[i + 1], i + 1));
                }

                waitForCompleteStatus(this.getOperationNumber(), nodes[nodes.length - 1], nodes.length - 1);

                reply = connection.sendMessage(boardHost, CommandMessage.Type.INITIATE_INTRANSIT_BOARD, new TransitBoardMessage(this.getOperationNumber(), boardName, nodes.length));
                if (reply.getType() != MessageReply.Type.OKAY)
                {
                    notifier.failed(new ShuffleStatus(reply.interpretPayloadAsError(), boardHost, null));
                    return;
                }

                reply = connection.sendMessage(nodes[nodes.length - 1], CommandMessage.Type.SHUFFLE_AND_MOVE_BOARD_TO_NODE, new PermuteAndMoveMessage(this.getOperationNumber(), boardName, nodes.length - 1, options.getTransformName(), options.getKeyID(), boardHost));
                if (reply.getType() != MessageReply.Type.OKAY)
                {
                    notifier.failed(new ShuffleStatus(reply.interpretPayloadAsError(), nodes[nodes.length - 1], null));
                    return;
                }

                waitForCompleteStatus(this.getOperationNumber(), boardHost, nodes.length);

                notifier.status(new ShuffleStatus("Returning (" + boardHost + "/" + nodes.length + ")", boardHost, nodes.length));

                reply = connection.sendMessage(boardHost, CommandMessage.Type.RETURN_TO_BOARD, new TransitBoardMessage(this.getOperationNumber(), boardName, nodes.length));
                if (reply.getType() != MessageReply.Type.OKAY)
                {
                    notifier.failed(new ShuffleStatus(reply.interpretPayloadAsError(), boardHost, null));
                    return;
                }

                waitForUnlockStatus(boardHost, boardName);

                notifier.completed();
            }
            catch (Exception e)
            {
                notifier.failed(new ShuffleStatus(e.toString(), "", e));
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
                    notifier.failed(reply.interpretPayloadAsError());
                    return;
                }

                String boardHost = DERUTF8String.getInstance(reply.getPayload()).getString();

                if (options.getKeyID() != null)
                {
                    String[] nodes = toOrderedSet(options.getNodesToUse()).toArray(new String[0]);

                    Map<String, AsymmetricKeyParameter> keyMap = new HashMap<>();
                    OutputStream proofLogStream = null;

                    keyMap = buildPublicKeyMap(nodes, options.getKeyID());

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
                        AsymmetricKeyParameter[] publicKeys = new AsymmetricKeyParameter[options.getThreshold()];
                        String[] nodesUsed = new String[options.getThreshold()];

                        // TODO: deal with drop outs
                        int count = 0;
                        int nodeCount = 0;
                        while (count != options.getThreshold())
                        {
                            partialDecryptResponses[count] = connection.sendMessage(nodes[nodeCount], CommandMessage.Type.PARTIAL_DECRYPT, new DecryptDataMessage(options.getKeyID(), data.getMessages()));
                            publicKeys[count] = keyMap.get(nodes[nodeCount]);
                            if (partialDecryptResponses[count].getType() == MessageReply.Type.OKAY)
                            {
                                nodesUsed[count] = nodes[nodeCount];
                                count++;
                            }
                            else
                            {
                                // TODO: maybe log
                                partialDecryptResponses[count] = null;
                            }
                            nodeCount++;
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
                        AsymmetricKeyParameter[] partialPubKeys = new AsymmetricKeyParameter[maxSequenceNo + 1];
                        String[] nodeNames = new String[maxSequenceNo + 1];

                        for (int i = 0; i != shareMessages.length; i++)
                        {
                            ShareMessage shareMsg = shareMessages[i];

                            partialDecrypts[shareMsg.getSequenceNo()] = PostedMessageDataBlock.getInstance(shareMsg.getShareData()).getMessages();
                            partialPubKeys[shareMsg.getSequenceNo()] = publicKeys[i];
                            nodeNames[shareMsg.getSequenceNo()] = nodesUsed[i];
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


                        BigInteger baseWeight = weights[baseIndex];
                        List<PostedMessage> postedMessages = messageBlock.getMessages();
                        List<byte[]> baseMessageBlock = partialDecrypts[baseIndex];

                        for (int messageIndex = 0; messageIndex != baseMessageBlock.size(); messageIndex++)
                        {
                            List<byte[]> proofList = verifyPoints(PairSequence.getInstance(domainParams.getCurve(), messageBlock.getMessages().get(messageIndex).getMessage()).getECPairs(), domainParams, nodeNames, partialPubKeys, partialDecrypts, weights, messageIndex);

                            ECPoint[] fulls = reassemblePoints(domainParams, partialDecrypts, weights, baseIndex, baseWeight, messageIndex);

                            int index = postedMessages.get(messageIndex).getIndex();

                            notifier.messageDownloaded(index, new PointSequence(fulls).getEncoded(), proofList);
                        }
                    }
                }
                else
                {
                    // assume plain text
                    for (; ; )
                    {
                        reply = connection.sendMessage(CommandMessage.Type.DOWNLOAD_BOARD_CONTENTS, new BoardDownloadMessage(boardName, 20));

                        if (reply.getType() == MessageReply.Type.OKAY)
                        {
                            PostedMessageBlock messageBlock = PostedMessageBlock.getInstance(reply.getPayload());

                            if (messageBlock.size() == 0)
                            {
                                break;
                            }

                            for (PostedMessage posted : messageBlock.getMessages())
                            {
                                notifier.messageDownloaded(posted.getIndex(), posted.getMessage(), new ArrayList<byte[]>());
                            }
                        }
                        else
                        {
                            notifier.failed("Failed: " + reply.getPayload().toString());
                            return;
                        }
                    }
                }

                reply = connection.sendMessage(CommandMessage.Type.BOARD_DOWNLOAD_UNLOCK, new BoardMessage(boardName));
                if (reply.getType() != MessageReply.Type.OKAY)
                {
                    notifier.failed(reply.interpretPayloadAsError());
                    return;
                }

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
            //
            // check we're talking to a node that's up!
            //
            Set<String>  activeNodes = connection.getActiveNodeNames();
            Set<String>  usableNodes = new LinkedHashSet<>();

            for (final String node : toOrderedSet(options.getNodesToUse()).toArray(new String[0]))
            {
                if (activeNodes.contains(node))
                {
                    usableNodes.add(node);
                }
            }

            String[] nodes = usableNodes.toArray(new String[usableNodes.size()]);

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

            // find the last general transcript as we need a copy of the cipher texts
            Integer lastKey = Integer.valueOf(0);

            for (Integer key : generalTranscripts.keySet())
            {
                if (key > lastKey)
                {
                    lastKey = key;
                }
            }

            File finalTranscriptFile;
            FileOutputStream transOut;

            try
            {
                finalTranscriptFile = File.createTempFile("ximix", ".gtr");
                transOut = new FileOutputStream(finalTranscriptFile);
            }
            catch (IOException e)
            {
                notifier.failed(e.toString());
                return;
            }

            generalTranscripts.put(lastKey, new TeeInputStream(generalTranscripts.get(lastKey), transOut)); // TODO: should assume generalTranscripts is modifiable
            if (!uploadTranscript(nodes, generalTranscripts, ".gtr"))
            {
                return;
            }

            try
            {
                transOut.close();
            }
            catch (IOException e)
            {
                notifier.failed(e.toString());
                return;
            }

            if (!uploadTranscript(nodes, witnessTranscripts, ".wtr"))
            {
                return;
            }

            //
            // initialise the decryption process
            //
            Map<String, RunnableFuture<MessageReply>> nodeFutureMap = new HashMap<>();

            for (final String node : nodes)
            {
                FutureTask<MessageReply> task = new FutureTask<>(new Callable<MessageReply>()
                {
                    @Override
                    public MessageReply call()
                        throws Exception
                    {
                        return connection.sendMessage(node, CommandMessage.Type.SETUP_PARTIAL_DECRYPT, new DecryptShuffledBoardMessage(options.getKeyID(), boardName, options.isPairingEnabled()));
                    }
                });

                nodeFutureMap.put(node, task);

                executor.submit(task);
            }

            for (String node : nodes)
            {
                try
                {

                    MessageReply reply = nodeFutureMap.get(node).get();
                    if (!reply.getType().equals(MessageReply.Type.OKAY))
                    {
                        notifier.failed(node + " reply " + reply.interpretPayloadAsError());
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

            int batchSize = 20; // TODO: configure
            PostedMessage[] finalMessages = new PostedMessage[batchSize];
            ASN1InputStream finalTranscript;
            FileInputStream finalTransIn;

            try
            {
                finalTransIn = new FileInputStream(finalTranscriptFile);
                CMSSignedDataParser cmsParser = new CMSSignedDataParser(new BcDigestCalculatorProvider(), new BufferedInputStream(finalTransIn));

                finalTranscript = new ASN1InputStream(cmsParser.getSignedContent().getContentStream());
            }
            catch (Exception e)
            {
                notifier.failed("Unable to open temporary transcript file: " + e.getMessage());
                return;
            }

            for (;;)
            {
                MessageReply[] partialDecryptResponses = new MessageReply[options.getThreshold()];
                AsymmetricKeyParameter[] publicKeys = new AsymmetricKeyParameter[options.getThreshold()];
                String[] nodesUsed = new String[options.getThreshold()];

                try
                {
                    Map<String, AsymmetricKeyParameter> keyMap = buildPublicKeyMap(nodes, options.getKeyID());

                    // TODO: deal with drop outs - in this case it's tricky, backend code will need to take into account a node
                    // might be asked to take over half way through.
                    int count = 0;
                    int nodeIndex = 0;
                    while (count != options.getThreshold())
                    {
                        partialDecryptResponses[count] = connection.sendMessage(nodes[nodeIndex], CommandMessage.Type.DOWNLOAD_PARTIAL_DECRYPTS, new DownloadShuffledBoardMessage(options.getKeyID(), boardName, batchSize)); // TODO: configure;
                        publicKeys[count] = keyMap.get(nodes[nodeIndex]);
                        if (partialDecryptResponses[count].getType() == MessageReply.Type.OKAY)
                        {
                            nodesUsed[count] = nodes[nodeIndex];
                            count++;
                        }
                        else
                        {
                            // TODO: maybe log
                            partialDecryptResponses[count] = null;
                        }
                        nodeIndex++;
                    }

                    int transCount = 0;
                    Object msg;
                    while (transCount < batchSize && (msg = finalTranscript.readObject()) != null)
                    {
                        finalMessages[transCount++] = PostedMessage.getInstance(msg);
                    }

                    PostedMessageDataBlock baseBlock = PostedMessageDataBlock.getInstance(ShareMessage.getInstance(partialDecryptResponses[0].getPayload()).getShareData());
                    if (baseBlock.size() == 0)
                    {
                        break;
                    }

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
                    AsymmetricKeyParameter[] partialPubKeys = new AsymmetricKeyParameter[maxSequenceNo + 1];
                    String[] nodeNames = new String[maxSequenceNo + 1];

                    for (int i = 0; i != shareMessages.length; i++)
                    {
                        ShareMessage shareMsg = shareMessages[i];

                        partialDecrypts[shareMsg.getSequenceNo()] = PostedMessageDataBlock.getInstance(shareMsg.getShareData()).getMessages();
                        partialPubKeys[shareMsg.getSequenceNo()] = publicKeys[i];
                        nodeNames[shareMsg.getSequenceNo()] = nodesUsed[i];
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

                    BigInteger baseWeight = weights[baseIndex];

                    for (int messageIndex = 0; messageIndex != baseBlock.size(); messageIndex++)
                    {
                        List<byte[]> proofs = verifyPoints(PairSequence.getInstance(domainParams.getCurve(), finalMessages[messageIndex].getMessage()).getECPairs(), domainParams, nodeNames, partialPubKeys, partialDecrypts, weights, messageIndex);

                        ECPoint[] fulls = reassemblePoints(domainParams, partialDecrypts, weights, baseIndex, baseWeight, messageIndex);

                        notifier.messageDownloaded(boardIndex++, new PointSequence(fulls).getEncoded(), proofs);
                    }
                }
                catch (Exception e)
                {
                    eventNotifier.notify(EventNotifier.Level.ERROR, "Exception in shuffle download: " + e.getMessage(), e);

                    notifier.failed(e.toString());
                }
            }

            try
            {
                finalTranscript.close();
            }
            catch (IOException e)
            {
                eventNotifier.notify(EventNotifier.Level.ERROR, "Unable to close final transcript file: " + e.getMessage(), e);
            }

            finalTranscriptFile.delete();       // TODO: perhaps check?

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
                        notifier.failed(node + " reply " + reply.interpretPayloadAsError());
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
                    notifier.failed(node + " reply " + reply.interpretPayloadAsError());
                    return false;
                }
            }
            return true;
        }
    }

    private List<byte[]> verifyPoints(ECPair[] cipherText, ECDomainParameters domainParams, String[] nodeNames, AsymmetricKeyParameter[] pubKeys, List<byte[]>[] partialDecrypts, BigInteger[] weights, int messageIndex)
        throws ServiceConnectionException
    {
        List<byte[]> proofList = new ArrayList<>();

        for (int wIndex = 0; wIndex < weights.length; wIndex++)
        {
            if (weights[wIndex] != null)
            {
                ECPublicKeyParameters nodeKey = (ECPublicKeyParameters)pubKeys[wIndex];
                PairSequenceWithProofs pairSequenceWithProofs = PairSequenceWithProofs.getInstance(domainParams.getCurve(), partialDecrypts[wIndex].get(messageIndex));

                ECDecryptionProof[] proofs = pairSequenceWithProofs.getECProofs();
                ECPair[] partials = pairSequenceWithProofs.getECPairs();

                if (proofs.length != partials.length)
                {
                    eventNotifier.notify(EventNotifier.Level.ERROR, "Partial decrypts and proofs differ in length from node " + nodeNames[wIndex]);
                    throw new ServiceConnectionException("Partial decrypts and proofs differ in length");
                }


                ECPoint[] decrypts = new ECPoint[partials.length];

                for (int i = 0; i != partials.length; i++)
                {
                    decrypts[i] = partials[i].getX();
                }

                boolean hasPassed = true;
                for (int i = 0; i != partials.length; i++)
                {
                    if (!proofs[i].isVerified(nodeKey, cipherText[i].getX(), partials[i].getX()))
                    {
                       hasPassed = false;
                    }
                }

                try
                {
                    proofList.add(new ChallengeLogMessage(messageIndex, wIndex, hasPassed, SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(nodeKey), decrypts, proofs).getEncoded());
                    if (hasPassed)
                    {
                        eventNotifier.notify(EventNotifier.Level.INFO, "Proof for message " + messageIndex + " for node " + nodeNames[wIndex] + " passed.");
                    }
                    else
                    {
                        eventNotifier.notify(EventNotifier.Level.ERROR, "Proof for message " + messageIndex + " for node " + nodeNames[wIndex] + " failed!");
                    }
                }
                catch (Exception e)
                {
                    eventNotifier.notify(EventNotifier.Level.ERROR, "Partial decrypts failed to encode from " + nodeNames[wIndex] + ": " + e.getMessage(), e);
                    throw new ServiceConnectionException("Partial decrypts failed to encode from " + nodeNames[wIndex] + ": " + e.getMessage(), e);
                }
            }
        }

        return proofList;
    }

    private ECPoint[] reassemblePoints(ECDomainParameters domainParams, List<byte[]>[] partialDecrypts, BigInteger[] weights, int baseIndex, BigInteger baseWeight, int messageIndex)
        throws ServiceConnectionException
    {
        List<byte[]> baseMessageBlock = partialDecrypts[baseIndex];

        PairSequenceWithProofs ps = PairSequenceWithProofs.getInstance(domainParams.getCurve(), baseMessageBlock.get(messageIndex));
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
                PairSequenceWithProofs pairSequenceWithProofs = PairSequenceWithProofs.getInstance(domainParams.getCurve(), partialDecrypts[wIndex].get(messageIndex));

                ECPair[] nPartials = pairSequenceWithProofs.getECPairs();
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

                String boardHost = getHostName(boardName);

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

    private Map<String, AsymmetricKeyParameter> buildPublicKeyMap(String[] nodes, String keyID)
        throws ServiceConnectionException
    {
        Map<String, AsymmetricKeyParameter> keyMap = new HashMap<>();

        for (String node : nodes)
        {
            MessageReply reply = connection.sendMessage(node, CommandMessage.Type.FETCH_PARTIAL_PUBLIC_KEY, new FetchPartialPublicKeyMessage(node, keyID));

            if (reply.getType() != MessageReply.Type.OKAY)
            {
                eventNotifier.notify(EventNotifier.Level.WARN, "Unable to get partial public key from " + node + ":" +  reply.interpretPayloadAsError());
            }

            try
            {
                PartialPublicKeyInfo partialPublicKeyInfo = PartialPublicKeyInfo.getInstance(reply.getPayload());

                keyMap.put(node, PublicKeyFactory.createKey(partialPublicKeyInfo.getPartialKeyInfo()));
            }
            catch (Exception e)
            {
                eventNotifier.notify(EventNotifier.Level.WARN, "Unable to get partial public key from " + node + ": " + e.getMessage(), e);
            }
        }

        return keyMap;
    }

}
