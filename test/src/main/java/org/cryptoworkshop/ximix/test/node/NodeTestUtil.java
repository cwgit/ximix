package org.cryptoworkshop.ximix.test.node;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.util.encoders.Hex;
import org.cryptoworkshop.ximix.common.config.ConfigException;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.node.XimixNode;
import org.cryptoworkshop.ximix.node.core.XimixNodeBuilder;

/**
 *
 */
public class NodeTestUtil
{

    private static HashMap<Thread, List<XimixNode>> nodesPerThread = new HashMap<>();

    public static void registerNode(XimixNode node)
    {
        Thread th = Thread.currentThread();
        if (!nodesPerThread.containsKey(th))
        {
            nodesPerThread.put(th, new ArrayList<XimixNode>());
        }

        nodesPerThread.get(th).add(node);
    }

    public static void launch(final XimixNode node, boolean register)
        throws Exception
    {
        if (register)
        {
            registerNode(node);
        }

        Thread th = new Thread(new Runnable()
        {
            @Override
            public void run()
            {
                node.start();
            }
        });
        th.setPriority(Thread.MIN_PRIORITY);
        th.setDaemon(true);
        th.start();
    }


    public static XimixNode getXimixNode(String networkConfig, String nodeConfigPath, EventNotifier handler)
        throws ConfigException
    {
        XimixNodeBuilder builder = new XimixNodeBuilder(ResourceAnchor.load(networkConfig)).withThrowableListener(handler);

        return builder.build(ResourceAnchor.load(nodeConfigPath));
    }



    public static XimixNode getXimixNode(String networkConfig, String nodeConfigPath)
        throws ConfigException
    {

       return getXimixNode(networkConfig,nodeConfigPath,new TestNotifier());

    }

    public static void shutdownNodes()
    {
        List<XimixNode> nodes = nodesPerThread.get(Thread.currentThread());
        if (nodes != null)
        {
            for (XimixNode node : nodes)
            {
                try
                {
                    node.shutdown(10, TimeUnit.SECONDS);
                }
                catch (Exception ex)
                {
                    ex.printStackTrace(System.err);
                }
            }
        }
    }


    /**
     * Print ln..
     * @param val
     */
    public static void printHexln(byte[] val)
    {
        System.out.println(new String(Hex.encode(val)));
    }


    /**
     * Print ln..
     * @param val
     */
    public static void printHexln(String prefix, byte[] val)
    {
        System.out.println(prefix+": "+new String(Hex.encode(val)));
    }
}
