package org.cryptoworkshop.ximix.monitor;

import org.bouncycastle.asn1.ASN1Encodable;
import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.config.ConfigObjectFactory;
import org.cryptoworkshop.ximix.common.message.*;
import org.cryptoworkshop.ximix.common.service.BasicService;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.Service;
import org.cryptoworkshop.ximix.mixnet.service.BoardHostingService;
import org.w3c.dom.Node;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.ArrayList;
import java.util.Map;

/**
 *
 */
public class NodeMonitorService
    extends BasicService
{
    public static final int MIN_STATISTICS_PERIOD = 1000;

    private final Config config;


    public NodeMonitorService(NodeContext nodeContext, Config config)
    {
        super(nodeContext);

        this.config = config;

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
            case GET_FULL_DETAILS:
            {
                nsm = new NodeStatusMessage();
                Runtime rt = Runtime.getRuntime();
                RuntimeMXBean mxBean = ManagementFactory.getRuntimeMXBean();

                NodeStatusMessage.Builder builder = new NodeStatusMessage.Builder();

                builder.put("name", nodeContext.getName());
                builder.put("vm.available-processors", rt.availableProcessors());
                builder.put("vm.free-memory", rt.freeMemory());
                builder.put("vm.total-memory", rt.totalMemory());
                builder.put("vm.up-time", mxBean.getUptime());
                builder.put("vm.start-time", mxBean.getStartTime());

                ArrayList<String> cap = new ArrayList<>();
                for (CapabilityMessage msg : nodeContext.getCapabilities())
                {
                    cap.add(msg.getType().name());
                }

                builder.put("node.capabilities", cap);

                nsm = builder.build();

            }
            break;

            case GET_INFO:
            {
                nsm = new NodeStatusMessage();
                Runtime rt = Runtime.getRuntime();
                RuntimeMXBean mxbean = ManagementFactory.getRuntimeMXBean();
                mxbean.getUptime();

                NodeStatusMessage.Builder builder = new NodeStatusMessage.Builder();

                builder.put("name", nodeContext.getName());
                builder.put("vm.vendor", mxbean.getVmVendor());
                builder.put("vm.vendor-name", mxbean.getVmName());
                builder.put("vm.vendor-version", mxbean.getVmVersion());
                builder.put("node.metadata", nodeContext.getDescription());

                nsm = builder.build();

            }
            break;

            case GET_STATISTICS:
            {

                NodeStatusMessage.Builder builder = new NodeStatusMessage.Builder();

//                Map<String, Object> accumulatedStats = new HashMap<>();

                Map<Service, Map<String, Object>> map = nodeContext.getServiceStatistics();


                for (Service service : map.keySet())
                {
                    if (service instanceof BoardHostingService)
                    {
                        builder.put("board.hosting.service", map.get(service));
                    }
                }

                builder.put("name", nodeContext.getName());
                nsm = builder.build();

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
