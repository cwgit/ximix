package org.cryptoworkshop.ximix.monitor;

import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.NodeStatusMessage;
import org.cryptoworkshop.ximix.common.message.NodeStatusRequestMessage;
import org.cryptoworkshop.ximix.common.service.AdminServicesConnection;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public class ClientNodeHealthMonitor
    implements NodeHealthMonitor
{
    private AdminServicesConnection connection = null;

    public ClientNodeHealthMonitor(AdminServicesConnection connection)
    {
        this.connection = connection;
    }

    @Override
    public NodeStatusMessage getLastStatistics(String name)
        throws ServiceConnectionException
    {
        NodeStatusMessage out = null;

        MessageReply reply = connection.sendMessage(name, CommandMessage.Type.NODE_STATISTICS, NodeStatusRequestMessage.forStatisticsRequest());
        if (reply.getType() == MessageReply.Type.ERROR)
        {
            System.out.println("Got error requesting statistics.");
        }
        else
        {
            out = NodeStatusMessage.getInstance(reply.getPayload());
        }


        return out;
    }

    @Override
    public List<NodeStatusMessage> getConnectedNodeInfo()
        throws ServiceConnectionException
    {
        List<NodeStatusMessage> out = new ArrayList<>();

        for (String name : connection.getActiveNodeNames())
        {
            MessageReply reply = connection.sendMessage(name, CommandMessage.Type.NODE_STATISTICS, NodeStatusRequestMessage.forStaticInfo());
            if (reply.getType() == MessageReply.Type.ERROR)
            {
                System.out.println("Got error requesting static info.");
            }
            else
            {
                out.add(NodeStatusMessage.getInstance(reply.getPayload()));
            }
        }


        return out;
    }

    @Override
    public NodeStatusMessage getFullInfo(String name)
        throws ServiceConnectionException
    {
        NodeStatusMessage out = null;

        MessageReply reply = connection.sendMessage(name, CommandMessage.Type.NODE_STATISTICS, NodeStatusRequestMessage.forFullDetails());
        if (reply.getType() == MessageReply.Type.ERROR)
        {
            System.out.println("Got error requesting vm info.");
        }
        else
        {
            out = NodeStatusMessage.getInstance(reply.getPayload());
        }


        return out;
    }

}