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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import org.cryptoworkshop.ximix.common.message.BoardMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.PermuteAndMoveMessage;
import org.cryptoworkshop.ximix.common.operation.Operation;
import org.cryptoworkshop.ximix.common.service.AdminServicesConnection;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.mixnet.DownloadOptions;
import org.cryptoworkshop.ximix.mixnet.ShuffleOptions;

public class ClientMixnetCommandService
    implements MixnetCommandService
{
    private Executor decouple = Executors.newSingleThreadExecutor();
    private Executor executor = Executors.newScheduledThreadPool(4);

    private AdminServicesConnection connection;

    public ClientMixnetCommandService(AdminServicesConnection connection)
    {
        this.connection = connection;
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
                for (String node : nodes)
                {
                    connection.sendMessage(node, CommandMessage.Type.SUSPEND_BOARD, new BoardMessage(boardName));
                }

                for (int i = 0; i != nodes.length; i++)
                {
                    String curNode = nodes[i];
                    String nextNode = nodes[(i + 1) % nodes.length];

                    connection.sendMessage(curNode, CommandMessage.Type.SHUFFLE_AND_MOVE_BOARD_TO_NODE, new PermuteAndMoveMessage(boardName, options.getTransformName(), options.getKeyID(), nextNode));
                }

                for (String node : nodes)
                {
                    connection.sendMessage(node, CommandMessage.Type.ACTIVATE_BOARD, new BoardMessage(boardName));
                }

                notifier.completed();
            }
            catch (Exception e)
            {
                notifier.failed(e.toString());
            }
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
//                connection.sendMessage(CommandMessage.Type.SUSPEND_BOARD, new BoardMessage(boardName));

//                for (int i = 0; i != nodes.length; i++)
//                {
//                    String curNode = nodes[i];
//                    String nextNode = nodes[(i + 1) % nodes.length];
//
//                    connection.sendMessage(curNode, CommandMessage.Type.SHUFFLE_AND_MOVE_BOARD_TO_NODE, new PermuteAndMoveMessage(boardName, options.getTransformName(), options.getKeyID(), nextNode));
//                }

                notifier.messageDownloaded(new byte[100]);
//
//                connection.sendMessage(CommandMessage.Type.ACTIVATE_BOARD, new BoardMessage(boardName));

                notifier.completed();
            }
            catch (Exception e)
            {
                notifier.failed(e.toString());
            }
        }
    }
}
