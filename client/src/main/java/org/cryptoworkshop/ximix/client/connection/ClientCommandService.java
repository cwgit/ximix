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

import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
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
import org.cryptoworkshop.ximix.client.MessageChooser;
import org.cryptoworkshop.ximix.client.ShuffleOperationListener;
import org.cryptoworkshop.ximix.client.ShuffleOptions;
import org.cryptoworkshop.ximix.client.ShuffleTranscriptsDownloadOperationListener;
import org.cryptoworkshop.ximix.common.asn1.board.PairSequence;
import org.cryptoworkshop.ximix.common.asn1.board.PointSequence;
import org.cryptoworkshop.ximix.common.asn1.message.BoardDownloadMessage;
import org.cryptoworkshop.ximix.common.asn1.message.BoardMessage;
import org.cryptoworkshop.ximix.common.asn1.message.BoardStatusMessage;
import org.cryptoworkshop.ximix.common.asn1.message.BoardUploadMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ChallengeLogMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ClientMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CreateBoardMessage;
import org.cryptoworkshop.ximix.common.asn1.message.DecryptDataMessage;
import org.cryptoworkshop.ximix.common.asn1.message.FetchPartialPublicKeyMessage;
import org.cryptoworkshop.ximix.common.asn1.message.FetchPublicKeyMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.PermuteAndMoveMessage;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessage;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessageBlock;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessageDataBlock;
import org.cryptoworkshop.ximix.common.asn1.message.ShareMessage;
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptBlock;
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptDownloadMessage;
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptQueryMessage;
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptQueryResponse;
import org.cryptoworkshop.ximix.common.asn1.message.TransitBoardMessage;
import org.cryptoworkshop.ximix.common.crypto.threshold.LagrangeWeightCalculator;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.common.util.Operation;
import org.cryptoworkshop.ximix.common.util.TranscriptType;

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
        Operation<DownloadOperationListener> op = new DownloadOp(boardName, options);

        op.addListener(defaultListener);

        executor.execute((Runnable)op);

        return op;
    }

    @Override
    public Operation<ShuffleTranscriptsDownloadOperationListener> downloadShuffleTranscripts(String boardName, long operationNumber, TranscriptType transcriptType, ShuffleTranscriptsDownloadOperationListener defaultListener, String... nodes)
        throws ServiceConnectionException
    {
        Operation<ShuffleTranscriptsDownloadOperationListener> op = new DownloadShuffleTranscriptsOp(boardName, operationNumber, transcriptType, nodes);

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

                String nextNode = nodes[0];

                // initial board state is copied to step 0 at start
                connection.sendMessage(nextNode, CommandMessage.Type.INITIATE_INTRANSIT_BOARD, new TransitBoardMessage(this.getOperationNumber(), boardName, 1));

                MessageReply startRep = connection.sendMessage(CommandMessage.Type.START_SHUFFLE_AND_MOVE_BOARD_TO_NODE, new PermuteAndMoveMessage(this.getOperationNumber(), boardName, 0, options.getTransformName(), options.getKeyID(), nextNode));
                if (startRep.getType() == MessageReply.Type.ERROR)
                {
                    notifier.failed(DERUTF8String.getInstance(startRep.getPayload()).getString());
                    return;
                }

                String boardHost = DERUTF8String.getInstance(startRep.getPayload()).getString();

                for (int i = 1; i < nodes.length; i++)
                {
                    String curNode = nextNode;

                    waitForCompleteStatus(this.getOperationNumber(), curNode, i);

                    nextNode = nodes[i];
                    connection.sendMessage(nextNode, CommandMessage.Type.INITIATE_INTRANSIT_BOARD, new TransitBoardMessage(this.getOperationNumber(), boardName, i + 1));

                    MessageReply reply = connection.sendMessage(curNode, CommandMessage.Type.SHUFFLE_AND_MOVE_BOARD_TO_NODE, new PermuteAndMoveMessage(this.getOperationNumber(), boardName, i, options.getTransformName(), options.getKeyID(), nextNode));
                    if (reply.getType() == MessageReply.Type.ERROR)
                    {
                        notifier.failed(DERUTF8String.getInstance(reply.getPayload()).getString());
                        return;
                    }
                }

                waitForCompleteStatus(this.getOperationNumber(), nextNode, nodes.length);

                connection.sendMessage(boardHost, CommandMessage.Type.INITIATE_INTRANSIT_BOARD, new TransitBoardMessage(this.getOperationNumber(), boardName, nodes.length + 1));

                connection.sendMessage(nextNode, CommandMessage.Type.SHUFFLE_AND_MOVE_BOARD_TO_NODE, new PermuteAndMoveMessage(this.getOperationNumber(), boardName, nodes.length, options.getTransformName(), options.getKeyID(), boardHost));

                waitForCompleteStatus(this.getOperationNumber(), boardHost, nodes.length + 1);

                connection.sendMessage(boardHost, CommandMessage.Type.RETURN_TO_BOARD, new TransitBoardMessage(this.getOperationNumber(), boardName, nodes.length + 1));

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
                    Thread.sleep(5000);  // TODO: configure?
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
                    Thread.sleep(5000);  // TODO: configure?
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
        private final String boardName;
        private final DownloadOptions options;

        public DownloadOp(String boardName, DownloadOptions options)
        {
            super(decouple, eventNotifier, DownloadOperationListener.class);

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
                                keyMap.put(node, PublicKeyFactory.createKey(SubjectPublicKeyInfo.getInstance(reply.getPayload().toASN1Primitive())));
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
                        reply = connection.sendMessage(CommandMessage.Type.DOWNLOAD_BOARD_CONTENTS, new BoardDownloadMessage(boardName, 10));

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
                        List<PostedMessage>  postedMessages = messageBlock.getMessages();

                        for (int messageIndex = 0; messageIndex != baseMessageBlock.size(); messageIndex++)
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
                    for (;;)
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
        }

        //
        // generate and log a zero knowledge proof.
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

            for (String node: nodes)
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

            for (String node: nodes)
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
                        eventNotifier.notify(EventNotifier.Level.INFO, "Challenge for message "  + messageIndex + " for node " + node + " passed.");
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
    
    private class DownloadShuffleTranscriptsOp
        extends Operation<ShuffleTranscriptsDownloadOperationListener>
        implements Runnable
    {
        private final String boardName;
        private final long operationOfInterestNumber;
        private final TranscriptType transcriptType;
        private final String[] nodes;

        public DownloadShuffleTranscriptsOp(String boardName, long operationOfInterestNumber, TranscriptType transcriptType, String... nodes)
        {
            super(decouple, eventNotifier, ShuffleTranscriptsDownloadOperationListener.class);

            this.boardName = boardName;
            this.operationOfInterestNumber = operationOfInterestNumber;
            this.transcriptType = transcriptType;
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

            for (int stepNo : response.stepNos())
            {
                PipedOutputStream pOut = null;

                for (;;)
                {                                                                                                                                                   // TODO: make configurable
                    reply = connection.sendMessage(node, CommandMessage.Type.DOWNLOAD_SHUFFLE_TRANSCRIPT, new TranscriptDownloadMessage(queryID, operationOfInterestNumber, stepNo, transcriptType, 10));

                    TranscriptBlock transcriptBlock = TranscriptBlock.getInstance(reply.getPayload());

                    if (transcriptBlock.size() == 0)
                    {
                        break;
                    }

                    if (pOut == null)
                    {

                        pOut = new PipedOutputStream();
                        PipedInputStream pIn = new PipedInputStream(pOut);

                        notifier.shuffleTranscriptArrived(operationOfInterestNumber, transcriptBlock.getStepNo(), pIn);
                    }

                    for (Enumeration<ASN1Encodable> en = transcriptBlock.getDetails().getObjects(); en.hasMoreElements();)
                    {
                        pOut.write(en.nextElement().toASN1Primitive().getEncoded());
                    }
                }

                if (pOut != null)
                {
                    pOut.close();
                }
            }
        }
    }
}
