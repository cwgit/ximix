package org.cryptoworkshop.ximix.client.connection;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cryptoworkshop.ximix.client.FullInfoData;
import org.cryptoworkshop.ximix.client.MonitorService;
import org.cryptoworkshop.ximix.client.NodeDetail;
import org.cryptoworkshop.ximix.client.StatisticsData;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.NodeStatusMessage;
import org.cryptoworkshop.ximix.common.asn1.message.NodeStatusRequestMessage;

/**
 * Internal implementation of the MonitorService interface. This class creates the messages which are then sent down
 * the ServicesConnection.
 */
class ClientNodeHealthMonitor
    implements MonitorService
{
    private AdminServicesConnection connection = null;
    private Map<String, NodeDetail> configuredNodeDetails;

    public ClientNodeHealthMonitor(AdminServicesConnection connection, Map<String, NodeDetail> configuredNodeDetails)
    {
        this.connection = connection;
        this.configuredNodeDetails = Collections.unmodifiableMap(configuredNodeDetails);
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
}