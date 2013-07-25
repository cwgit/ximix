package org.cryptoworkshop.ximix.monitor;

import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.message.*;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.Service;
import org.cryptoworkshop.ximix.common.statistics.CrossSection;
import org.cryptoworkshop.ximix.common.statistics.DefaultStatisticsCollector;

/**
 *
 */
public class NodeHealthMonitorService implements Service
{
    NodeContext context = null;
    DefaultStatisticsCollector statisticsCollector = null;

    public NodeHealthMonitorService()
    {

    }

    public NodeHealthMonitorService(NodeContext context, Config config)
    {
        this.context = context;
        statisticsCollector = new DefaultStatisticsCollector();
        statisticsCollector.start();

    }

    @Override
    public CapabilityMessage getCapability()
    {
        return null;
    }

    @Override
    public MessageReply handle(Message message)
    {

        //      availableProcessors = Runtime.getRuntime().availableProcessors();
        //      freeMemory = Runtime.getRuntime().freeMemory();
        //      totalMemory = Runtime.getRuntime().totalMemory();
        //      RuntimeMXBean mxbean = ManagementFactory.getRuntimeMXBean();
        //      mxbean.getUptime();


        NodeStatusRequestMessage req = NodeStatusRequestMessage.getInstance(message.getPayload());

        NodeStatusMessage nsm = null;

        switch (req.getType())
        {

            case RESET:
                break;
            case SET_PERIOD:
                break;
            case GET_STATIC_INFO:

                break;
            case GET_STATISTICS:
                CrossSection cs = statisticsCollector.pollOldestCrossSection();
                if (cs == null)
                {
                    nsm = NodeStatusMessage.NULL_MESSAGE;
                }
                else
                {
                    nsm = NodeStatusMessage.getInstance(cs, cs.getStartTime());
                }
                break;
        }


        MessageReply reply = new MessageReply(MessageReply.Type.OKAY, nsm);

        return reply;
    }

    /**
     *
     * @return
     */
    private NodeStatusMessage getStaticInfo()
    {
       NodeStatusMessage nsm = new NodeStatusMessage();

        return nsm;
    }

    @Override
    public boolean isAbleToHandle(Message message)
    {
        Enum e = message.getType();
        return CommandMessage.Type.NODE_STATISTICS == e;
    }


}
