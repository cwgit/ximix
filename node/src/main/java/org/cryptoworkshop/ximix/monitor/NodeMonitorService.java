package org.cryptoworkshop.ximix.monitor;

import org.bouncycastle.asn1.ASN1Encodable;
import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.config.ConfigObjectFactory;
import org.cryptoworkshop.ximix.common.message.*;
import org.cryptoworkshop.ximix.common.service.BasicService;
import org.cryptoworkshop.ximix.common.service.ListeningSocketInfo;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.Service;
import org.cryptoworkshop.ximix.mixnet.service.BoardHostingService;
import org.w3c.dom.Node;

import java.lang.management.GarbageCollectorMXBean;
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
    private final int hash;
    private final ListeningSocketInfo socketInfo;
    private long totalGC = 0;
    private long gcTime = 0;

    public NodeMonitorService(NodeContext nodeContext, Config config)
    {
        super(nodeContext);
        this.config = config;

        socketInfo = nodeContext.getListeningSocketInfo();

        hash = socketInfo.hashCode();

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

                Runtime rt = Runtime.getRuntime();
                RuntimeMXBean mxBean = ManagementFactory.getRuntimeMXBean();

                NodeStatusMessage.Builder builder = new NodeStatusMessage.Builder(hash);

                builder.put("name", nodeContext.getName());
                builder.put("hash", hash);

                builder.put("vm", "vendor", mxBean.getVmVendor());
                builder.put("vm", "name", mxBean.getVmName());
                builder.put("vm", "vendor-version", mxBean.getVmVersion());
                builder.put("vm", "available-processors", rt.availableProcessors());
                builder.put("vm", "total-memory", rt.totalMemory());
                builder.put("vm", "start-time", mxBean.getStartTime());

                builder.put("socket", "port", socketInfo.getPort());
                builder.put("socket", "bind-address", socketInfo.getBindAddress());
                builder.put("socket", "backlog", socketInfo.getBacklog());

                builder.put("info", nodeContext.getDescription());


                ArrayList<String> cap = new ArrayList<>();
                for (CapabilityMessage msg : nodeContext.getCapabilities())
                {
                    cap.add(msg.getType().name());
                }

                builder.put("node.capabilities", cap);

                nsm = builder.build();

            }
            break;


            case GET_STATISTICS:
            {
                //
                // Form GC stats
                //

                long totalGC = 0;
                long gcTime = 0;

                for (GarbageCollectorMXBean gc :
                    ManagementFactory.getGarbageCollectorMXBeans())
                {

                    long count = gc.getCollectionCount();

                    if (count >= 0)
                    {
                        totalGC += count;
                    }

                    long time = gc.getCollectionTime();

                    if (time >= 0)
                    {
                        gcTime += time;
                    }
                }


                RuntimeMXBean mxBean = ManagementFactory.getRuntimeMXBean();
                Runtime rt = Runtime.getRuntime();


                NodeStatusMessage.Builder builder = new NodeStatusMessage.Builder(hash);

                Map<Service, Map<String, Object>> map = null;
                try
                {
                    map = nodeContext.getServiceStatistics();
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                }


                for (Service service : map.keySet())
                {
                    if (service instanceof BoardHostingService)
                    {
                        if (!map.get(service).isEmpty())
                        {
                            builder.put("bhs:bhs-title", map.get(service));
                        }
                    }
                }

                builder.put("name", nodeContext.getName());
                builder.put("hash", hash);
                builder.put("vm.up-time", mxBean.getUptime());
                builder.put("vm.start-time", mxBean.getStartTime());
                builder.put("vm.free-memory", rt.freeMemory());
                builder.put("vm.gc.count.delta", totalGC - this.totalGC);
                builder.put("vm.gc.time.delta", gcTime - this.gcTime);


                nsm = builder.build();

                this.gcTime = gcTime;
                this.totalGC = totalGC;


            }
            break;
        }


        MessageReply reply = new MessageReply(MessageReply.Type.OKAY, nsm);

        return reply;
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
