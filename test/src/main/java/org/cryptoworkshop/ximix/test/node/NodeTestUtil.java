package org.cryptoworkshop.ximix.test.node;

import org.cryptoworkshop.ximix.common.conf.ConfigException;
import org.cryptoworkshop.ximix.node.ThrowableHandler;
import org.cryptoworkshop.ximix.node.XimixNode;
import org.cryptoworkshop.ximix.node.XimixNodeBuilder;

/**
 *
 */
public class NodeTestUtil
{
     public static void launch(final XimixNode node) throws Exception
     {
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

    public static XimixNode getXimixNode(String networkConfig, String nodeConfigPath)
        throws ConfigException
    {
        XimixNodeBuilder builder = new XimixNodeBuilder(ResourceAnchor.load(networkConfig)).withThrowableHandler(new ThrowableHandler()
        {
            @Override
            public void handle(Throwable throwable)
            {
                throwable.printStackTrace();
            }
        });

        return builder.build(ResourceAnchor.load(nodeConfigPath));
    }
}
