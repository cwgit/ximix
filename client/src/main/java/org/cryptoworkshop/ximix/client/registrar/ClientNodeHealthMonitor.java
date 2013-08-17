package org.cryptoworkshop.ximix.client.registrar;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.cryptoworkshop.ximix.client.MonitorService;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.NodeStatusMessage;
import org.cryptoworkshop.ximix.common.asn1.message.NodeStatusRequestMessage;
import org.cryptoworkshop.ximix.common.service.AdminServicesConnection;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;

/**
 *
 */
public class ClientNodeHealthMonitor
    implements MonitorService
{
    private AdminServicesConnection connection = null;

    public ClientNodeHealthMonitor(AdminServicesConnection connection)
    {
        this.connection = connection;
    }

    @Override
    public NodeStatusMessage getStatistics(String name)
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
    public List<NodeStatusMessage> getFullInfo()
        throws ServiceConnectionException
    {
        List<NodeStatusMessage> out = new ArrayList<>();

        for (String name : connection.getActiveNodeNames())
        {
            MessageReply reply = connection.sendMessage(name, CommandMessage.Type.NODE_STATISTICS, NodeStatusRequestMessage.forFullDetails());
            if (reply.getType() == MessageReply.Type.ERROR)
            {
                System.out.println("Got error requesting vm info.");
            }
            else
            {
                out.add(NodeStatusMessage.getInstance(reply.getPayload()));
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
    public NodeStatusMessage getFullInfo(String name)
    {
        MessageReply reply = null;
        try
        {
            reply = connection.sendMessage(name, CommandMessage.Type.NODE_STATISTICS, NodeStatusRequestMessage.forFullDetails());
        }
        catch (ServiceConnectionException e)
        {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }


        if (reply.getType() == MessageReply.Type.ERROR)
        {
            return null;
        }

        return NodeStatusMessage.getInstance(reply.getPayload());
    }


}