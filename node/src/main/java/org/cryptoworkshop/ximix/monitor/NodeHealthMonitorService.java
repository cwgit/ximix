package org.cryptoworkshop.ximix.monitor;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.config.ConfigException;
import org.cryptoworkshop.ximix.common.config.ConfigObjectFactory;
import org.cryptoworkshop.ximix.common.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.NodeStatusMessage;
import org.cryptoworkshop.ximix.common.message.NodeStatusRequestMessage;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.Service;
import org.cryptoworkshop.ximix.common.statistics.CrossSection;
import org.cryptoworkshop.ximix.common.statistics.DefaultStatisticsCollector;
import org.cryptoworkshop.ximix.common.statistics.StatisticCollector;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 *
 */
public class NodeHealthMonitorService
    implements Service
{
    public static final int MIN_STATISTICS_PERIOD = 1000;
    private final NodeContext context;
    private final DefaultStatisticsCollector statisticsCollector;
    private final Config config;
    private List<HealthMonitorMetaDataConfig> metaData;
    private Map metaDataMap;


    public NodeHealthMonitorService(NodeContext context, Config config)
    {
        this.context = context;
        this.config = config;
        statisticsCollector = new DefaultStatisticsCollector();
        statisticsCollector.start();

        try
        {
            metaData = config.getConfigObjects("meta-data", new HealthMonitorConfigFactory());

            metaDataMap = new HashMap();
            for (HealthMonitorMetaDataConfig h : metaData)
            {
                metaDataMap.put(h.getName(), h.getValue());
            }


        }
        catch (ConfigException e)
        {

            //TODO log, throws if no meta data, is this desired behavior.
        }

    }


    private void applyConfig(Config cfg)
    {

    }

    @Override
    public CapabilityMessage getCapability()
    {
        return new CapabilityMessage(CapabilityMessage.Type.NODE_HEALTH, new ASN1Encodable[0]);
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

            case GET_FULL_DETAILS:
            {
                nsm = new NodeStatusMessage();
                Runtime rt = Runtime.getRuntime();
                RuntimeMXBean mxBean = ManagementFactory.getRuntimeMXBean();
                nsm.putValue("name", context.getName());
                nsm.putValue("vm.available-processors", rt.availableProcessors());
                nsm.putValue("vm.free-memory", rt.freeMemory());
                nsm.putValue("vm.total-memory", rt.totalMemory());
                nsm.putValue("vm.up-time", mxBean.getUptime());
                nsm.putValue("vm.start-time", mxBean.getStartTime());

                ArrayList<String> cap = new ArrayList<>();
                for (CapabilityMessage msg : context.getCapabilities())
                {
                    cap.add(msg.getType().name());
                }

                nsm.putValue("node.capabilities", cap);
            }
            break;

            case GET_INFO:
            {
                nsm = new NodeStatusMessage();
                Runtime rt = Runtime.getRuntime();
                RuntimeMXBean mxbean = ManagementFactory.getRuntimeMXBean();
                mxbean.getUptime();
                nsm.putValue("name", context.getName());
                nsm.putValue("vm.vendor", mxbean.getVmVendor());
                nsm.putValue("vm.vendor-name", mxbean.getVmName());
                nsm.putValue("vm.vendor-version", mxbean.getVmVersion());

                if (metaDataMap != null)
                {
                    nsm.putValue("node.metadata", metaDataMap);
                }


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
                    nsm.putValue("name", context.getName());
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

    public StatisticCollector getStatisticCollector()
    {
        return statisticsCollector;
    }


    private class HealthMonitorConfigFactory
        implements ConfigObjectFactory<HealthMonitorMetaDataConfig>
    {

        @Override
        public HealthMonitorMetaDataConfig createObject(Node configNode)
        {
            return new HealthMonitorMetaDataConfig(configNode);
        }
    }

    private class HealthMonitorMetaDataConfig
    {
        private String name = null;
        private String value = null;

        public HealthMonitorMetaDataConfig(Node configNode)
        {

            name = configNode.getAttributes().getNamedItem("name").getTextContent();
            value = configNode.getTextContent();
        }

        private String getName()
        {
            return name;
        }

        private String getValue()
        {
            return value;
        }
    }
}
