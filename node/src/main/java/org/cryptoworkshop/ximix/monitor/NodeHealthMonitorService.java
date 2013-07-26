package org.cryptoworkshop.ximix.monitor;

import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.message.*;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.Service;
import org.cryptoworkshop.ximix.common.statistics.CrossSection;
import org.cryptoworkshop.ximix.common.statistics.DefaultStatisticsCollector;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;

/**
 *
 */
public class NodeHealthMonitorService
    implements Service
{
    public static final int MIN_STATISTICS_PERIOD = 1000;
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
        NodeStatusRequestMessage req = NodeStatusRequestMessage.getInstance(message.getPayload());

        NodeStatusMessage nsm = null;

        switch (req.getType())
        {

            case TRIM:
                int totalCount = req.getToCount();
                if (totalCount < 1)
                {
                    totalCount = 1;
                }
                statisticsCollector.trim(totalCount);

                break;
            case SET_PERIOD:
                int period = req.getPeriod();
                if (period < 1000)
                {
                    period = MIN_STATISTICS_PERIOD;
                }
                statisticsCollector.setDurationMillis(period);
                break;

            case GET_VM_INFO:
            {
                nsm = new NodeStatusMessage();
                Runtime rt = Runtime.getRuntime();
                RuntimeMXBean mxBean = ManagementFactory.getRuntimeMXBean();
                nsm.putValue("vm.available-processors", rt.availableProcessors());
                nsm.putValue("vm.free-memory", rt.freeMemory());
                nsm.putValue("vm.total-memory", rt.totalMemory());
                nsm.putValue("vm.up-time", mxBean.getUptime());
                nsm.putValue("vm.start-time", mxBean.getStartTime());
            }
            break;

            case GET_STATIC_INFO:
            {
                nsm = new NodeStatusMessage();
                Runtime rt = Runtime.getRuntime();
                RuntimeMXBean mxbean = ManagementFactory.getRuntimeMXBean();
                mxbean.getUptime();
                nsm.putValue("vm.vendor", mxbean.getVmVendor());
                nsm.putValue("vm.vendor-name", mxbean.getVmName());
                nsm.putValue("vm.vendor-version", mxbean.getVmVersion());
            }
            break;

            case GET_STATISTICS:
            {
                CrossSection cs = statisticsCollector.pollOldestCrossSection();
                if (cs == null)
                {
                    nsm = NodeStatusMessage.NULL_MESSAGE;
                }
                else
                {
                    nsm = NodeStatusMessage.getInstance(cs, cs.getStartTime());
                }
            }
            break;
        }


        MessageReply reply = new MessageReply(MessageReply.Type.OKAY, nsm);

        return reply;
    }

    /**
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
