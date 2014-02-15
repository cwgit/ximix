package org.cryptoworkshop.ximix.client.connection;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.ASN1Sequence;
import org.cryptoworkshop.ximix.client.BoardDetail;
import org.cryptoworkshop.ximix.client.FullInfoData;
import org.cryptoworkshop.ximix.client.MonitorService;
import org.cryptoworkshop.ximix.client.NetworkBoardListener;
import org.cryptoworkshop.ximix.client.NodeDetail;
import org.cryptoworkshop.ximix.client.StatisticsData;
import org.cryptoworkshop.ximix.common.asn1.message.BoardDetailMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.NodeStatusMessage;
import org.cryptoworkshop.ximix.common.asn1.message.NodeStatusRequestMessage;
import org.cryptoworkshop.ximix.common.util.DecoupledListenerHandlerFactory;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.common.util.ListenerHandler;

/**
 * Internal implementation of the MonitorService interface. This class creates the messages which are then sent down
 * the ServicesConnection.
 */
class ClientNodeHealthMonitor
    implements MonitorService
{
    private final Map<String, BoardDetailMessage> networkBoardDetails = new HashMap<>();

    private AdminServicesConnection connection = null;
    private Map<String, NodeDetail> configuredNodeDetails;
    private ScheduledExecutorService taskExecutor = Executors.newSingleThreadScheduledExecutor();
    private ScheduledExecutorService notifyExecutor = Executors.newSingleThreadScheduledExecutor();

    private final ListenerHandler<NetworkBoardListener> boardListenerHandler;
    private final NetworkBoardListener boardNotifier;

    public ClientNodeHealthMonitor(AdminServicesConnection connection, Map<String, NodeDetail> configuredNodeDetails)
    {
        this.connection = connection;
        this.configuredNodeDetails = Collections.unmodifiableMap(configuredNodeDetails);
        this.boardListenerHandler = new DecoupledListenerHandlerFactory(notifyExecutor, connection.getEventNotifier()).createHandler(NetworkBoardListener.class);
        this.boardNotifier = boardListenerHandler.getNotifier();

        taskExecutor.schedule(new BoardMonitorTask(), 1, TimeUnit.SECONDS);
    }

    @Override
    public void addBulletinBoardListener(final NetworkBoardListener boardListener)
    {
        taskExecutor.execute(new Runnable()
        {
            @Override
            public void run()
            {
                // inform listener of the current state.
                for (final BoardDetailMessage detailMsg : networkBoardDetails.values())
                {
                    notifyExecutor.execute(new Runnable()
                    {
                        @Override
                        public void run()
                        {
                            boardListener.boardChanged(detailMsg.getBoardName(), new BoardDetail(detailMsg.getHost(), detailMsg.getMessageCount(), detailMsg.getBackupHost()));
                        }
                    });
                }
                // add to notifier.
                boardListenerHandler.addListener(boardListener);
            }
        });
    }

    @Override
    public Map<String, NodeDetail> getConfiguredNodeDetails()
    {
        return configuredNodeDetails;
    }

    @Override
    public StatisticsData getStatistics(String name)
        throws ServiceConnectionException
    {
        MessageReply reply = connection.sendMessage(name, CommandMessage.Type.NODE_STATISTICS, NodeStatusRequestMessage.forStatisticsRequest());
        if (reply.getType() == MessageReply.Type.ERROR)
        {
            System.out.println("Got error requesting statistics.");
        }
        else
        {
            return new StatisticsData(NodeStatusMessage.Statistics.getInstance(reply.getPayload()).getValues());
        }


        return new StatisticsData(new HashMap<String, Object>());
    }

    @Override
    public List<FullInfoData> getFullInfo()
        throws ServiceConnectionException
    {
        List<FullInfoData> out = new ArrayList<>();

        for (String name : connection.getActiveNodeNames())
        {
            MessageReply reply = connection.sendMessage(name, CommandMessage.Type.NODE_STATISTICS, NodeStatusRequestMessage.forFullDetails());
            if (reply.getType() == MessageReply.Type.ERROR)
            {
                System.out.println("Got error requesting vm info.");
            }
            else
            {
                out.add(new FullInfoData(NodeStatusMessage.Info.getInstance(reply.getPayload()).getValues()));
            }
        }

        return out;
    }

    @Override
    public Set<String> getConnectedNodeNames()
    {
        return connection.getActiveNodeNames();
    }

    @Override
    public NodeStatusMessage.Info getFullInfo(String name)
        throws ServiceConnectionException
    {
        MessageReply reply = connection.sendMessage(name, CommandMessage.Type.NODE_STATISTICS, NodeStatusRequestMessage.forFullDetails());

        if (reply.getType() == MessageReply.Type.ERROR)
        {
            return null;
        }

        return NodeStatusMessage.Info.getInstance(reply.getPayload());
    }

    @Override
    public void shutdown()
        throws ServiceConnectionException
    {
        taskExecutor.shutdownNow();
        notifyExecutor.shutdownNow();
        connection.shutdown();
    }

    private class BoardMonitorTask
        implements Runnable
    {

        @Override
        public void run()
        {
            for (String node : getConnectedNodeNames())
            {
                try
                {
                    MessageReply reply = connection.sendMessage(node, CommandMessage.Type.GET_BOARD_DETAILS, NodeStatusRequestMessage.forFullDetails());
                    if (reply.getType() != MessageReply.Type.OKAY)
                    {
                        continue; // ignore
                    }

                    ASN1Sequence seq = ASN1Sequence.getInstance(reply.getPayload());
                    for (Enumeration en = seq.getObjects(); en.hasMoreElements();)
                    {
                        BoardDetailMessage detailMsg = BoardDetailMessage.getInstance(en.nextElement());

                        BoardDetailMessage existing = networkBoardDetails.get(detailMsg.getBoardName());
                        if (existing == null || !detailMsg.equals(existing))
                        {
                            networkBoardDetails.put(detailMsg.getBoardName(), detailMsg);
                            boardNotifier.boardChanged(detailMsg.getBoardName(), new BoardDetail(detailMsg.getHost(), detailMsg.getMessageCount(), detailMsg.getBackupHost()));
                        }
                    }
                }
                catch (Exception e)
                {
                    connection.getEventNotifier().notify(EventNotifier.Level.WARN, "Exception in board monitor: " + e.getMessage(), e);
                }
            }

            taskExecutor.schedule(this, 5, TimeUnit.SECONDS);
        }
    }
}