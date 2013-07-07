package org.cryptoworkshop.ximix.test.node;

import org.cryptoworkshop.ximix.common.conf.ConfigException;
import org.cryptoworkshop.ximix.common.handlers.ThrowableHandler;
import org.cryptoworkshop.ximix.node.XimixNode;
import org.cryptoworkshop.ximix.node.XimixNodeBuilder;

import java.util.*;
import java.util.concurrent.TimeUnit;

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


    public static XimixNode getXimixNode(String networkConfig, String nodeConfigPath, ThrowableHandler handler)
        throws ConfigException
    {
        XimixNodeBuilder builder = new XimixNodeBuilder(ResourceAnchor.load(networkConfig)).withThrowableHandler(handler);

        return builder.build(ResourceAnchor.load(nodeConfigPath));
    }



    public static XimixNode getXimixNode(String networkConfig, String nodeConfigPath)
        throws ConfigException
    {

       return getXimixNode(networkConfig,nodeConfigPath,new ThrowableHandler()
        {
            @Override
            public void handle(Throwable throwable)
            {
                throwable.printStackTrace();
            }
        });

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

}
