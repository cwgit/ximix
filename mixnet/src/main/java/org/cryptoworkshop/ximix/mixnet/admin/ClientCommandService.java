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
package org.cryptoworkshop.ximix.mixnet.admin;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.board.asn1.PairSequence;
import org.cryptoworkshop.ximix.common.board.asn1.PointSequence;
import org.cryptoworkshop.ximix.common.message.BoardDownloadMessage;
import org.cryptoworkshop.ximix.common.message.BoardMessage;
import org.cryptoworkshop.ximix.common.message.BoardStatusMessage;
import org.cryptoworkshop.ximix.common.message.ClientMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.DecryptDataMessage;
import org.cryptoworkshop.ximix.common.message.FetchPublicKeyMessage;
import org.cryptoworkshop.ximix.common.message.MessageBlock;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.PermuteAndMoveMessage;
import org.cryptoworkshop.ximix.common.message.PermuteAndReturnMessage;
import org.cryptoworkshop.ximix.common.operation.Operation;
import org.cryptoworkshop.ximix.common.service.AdminServicesConnection;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.crypto.threshold.LagrangeWeightCalculator;
import org.cryptoworkshop.ximix.mixnet.DownloadOptions;
import org.cryptoworkshop.ximix.mixnet.ShuffleOptions;

public class ClientCommandService
    implements CommandService
{
    private Executor decouple = Executors.newSingleThreadExecutor();
    private Executor executor = Executors.newScheduledThreadPool(4);

    private AdminServicesConnection connection;

    public ClientCommandService(AdminServicesConnection connection)
    {
        this.connection = connection;
    }

    @Override
    public void shutdown() throws ServiceConnectionException
    {
        connection.close();
    }

    @Override
    public Operation<ShuffleOperationListener> doShuffleAndMove(String boardName, ShuffleOptions options, String... nodes)
        throws ServiceConnectionException
    {
        Operation<ShuffleOperationListener> op = new ShuffleOp(boardName, options, nodes);

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
    public List<NodeDetail> getNodeDetails()
        throws ServiceConnectionException
    {
        ArrayList<NodeDetail> nodes = new ArrayList<NodeDetail>();
        NodeDetail nd = new NodeDetail();
        nodes.add(nd);
        return nodes;
    }

    @Override
    public List<NodeHealth> getNodeHealth(String... nodes)
        throws ServiceConnectionException
    {

        ArrayList<NodeHealth> healths = new ArrayList<>();

        healths.add(new NodeHealth());


        return healths;
    }

    @Override
    public List<NodeStatistics> getNodeStatistics(String... nodes)
    {
        ArrayList<NodeStatistics> nodeStatistics = new ArrayList<>();
        nodeStatistics.add(new NodeStatistics());

        return nodeStatistics;
    }

    @Override
    public void shutdown(String... nodes)
    {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public void restart(String... nodes)
    {
        //To change body of implemented methods use File | Settings | File Templates.
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
            super(decouple, ShuffleOperationListener.class);

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

                connection.sendMessage(nextNode, CommandMessage.Type.INITIATE_INTRANSIT_BOARD, new BoardMessage(boardName));

                MessageReply startRep = connection.sendMessage(CommandMessage.Type.START_SHUFFLE_AND_MOVE_BOARD_TO_NODE, new PermuteAndMoveMessage(boardName, options.getTransformName(), options.getKeyID(), nextNode));
                String boardHost = DERUTF8String.getInstance(startRep.getPayload()).getString();

                for (int i = 1; i < nodes.length; i++)
                {
                    String curNode = nextNode;

                    whatForCompleteStatus(curNode);

                    nextNode = nodes[i];
                    connection.sendMessage(nextNode, CommandMessage.Type.INITIATE_INTRANSIT_BOARD, new BoardMessage(boardName));

                    connection.sendMessage(curNode, CommandMessage.Type.SHUFFLE_AND_MOVE_BOARD_TO_NODE, new PermuteAndMoveMessage(boardName, options.getTransformName(), options.getKeyID(), nextNode));
                }

                whatForCompleteStatus(nextNode);

                connection.sendMessage(boardHost, CommandMessage.Type.INITIATE_INTRANSIT_BOARD, new BoardMessage(boardName));

                connection.sendMessage(nextNode, CommandMessage.Type.SHUFFLE_AND_RETURN_BOARD, new PermuteAndReturnMessage(boardName, options.getTransformName(), options.getKeyID()));

                whatForCompleteStatus(boardHost);

                connection.sendMessage(CommandMessage.Type.BOARD_SHUFFLE_UNLOCK, new BoardMessage(boardName));

                notifier.completed();
            }
            catch (Exception e)
            {
                notifier.failed(e.toString());
            }
        }

        private void whatForCompleteStatus(String curNode)
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

                tReply = connection.sendMessage(curNode, CommandMessage.Type.FETCH_BOARD_STATUS, new BoardMessage(boardName));
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
            super(decouple, DownloadOperationListener.class);

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

                    for (;;)
                    {
                        reply = connection.sendMessage(CommandMessage.Type.DOWNLOAD_BOARD_CONTENTS, new BoardDownloadMessage(boardName, 10));

                        MessageBlock data = MessageBlock.getInstance(reply.getPayload());

                        if (data.size() == 0)
                        {
                            break;
                        }

                        MessageReply[] partialDecryptResponses = new MessageReply[options.getThreshold()];

                        // TODO: deal with drop outs
                        for (int i = 0; i != options.getThreshold(); i++)
                        {
                            String curNode = nodes[i];

                            partialDecryptResponses[i] = connection.sendMessage(curNode, CommandMessage.Type.PARTIAL_DECRYPT, new DecryptDataMessage(options.getKeyID(), data.getMessages()));
                        }

                        MessageReply keyReply = connection.sendMessage(ClientMessage.Type.FETCH_PUBLIC_KEY, new FetchPublicKeyMessage(options.getKeyID()));

                        SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfo.getInstance(keyReply.getPayload());

                        ECDomainParameters domainParams = ((ECPublicKeyParameters)PublicKeyFactory.createKey(pubKeyInfo)).getParameters();

                        LagrangeWeightCalculator calculator = new LagrangeWeightCalculator(options.getThreshold(), domainParams.getN());

                        BigInteger[] weights = calculator.computeWeights(partialDecryptResponses);

                        // weighting
                        List<byte[]>[] partialDecrypts = new List[options.getThreshold()];

                        for (int i = 0; i != partialDecrypts.length; i++)
                        {
                            partialDecrypts[i] = MessageBlock.getInstance(partialDecryptResponses[i].getPayload()).getMessages();
                        }

                        for (int messageIndex = 0; messageIndex != partialDecrypts[0].size(); messageIndex++)
                        {
                            PairSequence ps = PairSequence.getInstance(domainParams.getCurve(), partialDecrypts[0].get(messageIndex));
                            ECPoint[] weightedDecryptions = new ECPoint[ps.size()];
                            ECPoint[] fulls = new ECPoint[ps.size()];

                            ECPair[]  partials = ps.getECPairs();
                            for (int i = 0; i != weightedDecryptions.length; i++)
                            {
                                weightedDecryptions[i] = partials[i].getX().multiply(weights[0]);
                            }
                            for (int wIndex = 1; wIndex < weights.length; wIndex++)
                            {
                                ECPair[]  nPartials = PairSequence.getInstance(domainParams.getCurve(), partialDecrypts[wIndex].get(messageIndex)).getECPairs();
                                for (int i = 0; i != weightedDecryptions.length; i++)
                                {
                                    weightedDecryptions[i] = weightedDecryptions[i].add(nPartials[i].getX().multiply(weights[wIndex]));
                                }
                            }

                            for (int i = 0; i != weightedDecryptions.length; i++)
                            {
                                fulls[i] = partials[i].getY().add(weightedDecryptions[i].negate());
                            }

                            notifier.messageDownloaded(new PointSequence(fulls).getEncoded());
                        }
                    }
                }
                else
                {
                    // assume plain text
                    for (;;)
                    {
                        reply = connection.sendMessage(CommandMessage.Type.DOWNLOAD_BOARD_CONTENTS, new BoardDownloadMessage(boardName, 10));

                        MessageBlock data = MessageBlock.getInstance(reply.getPayload());

                        if (data.size() == 0)
                        {
                            break;
                        }

                        List<byte[]> messages = data.getMessages();

                        for (int i = 0 ; i != messages.size(); i++)
                        {
                            notifier.messageDownloaded(messages.get(i));
                        }
                    }
                }

                connection.sendMessage(CommandMessage.Type.BOARD_DOWNLOAD_UNLOCK, new BoardMessage(boardName));

                notifier.completed();
            }
            catch (Exception e)
            {
                e.printStackTrace();
                notifier.failed(e.toString());
            }
        }
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

    private static class CaseInsensitiveComparator
        implements Comparator<String>
    {
        @Override
        public int compare(String s1, String s2)
        {
            return s1.compareToIgnoreCase(s2);
        }
    }
}
