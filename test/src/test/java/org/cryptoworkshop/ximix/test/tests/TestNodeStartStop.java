package org.cryptoworkshop.ximix.test.tests;

import junit.framework.TestCase;
import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.util.ExtendedFuture;
import org.cryptoworkshop.ximix.common.util.FutureComplete;
import org.cryptoworkshop.ximix.node.ThrowableHandler;
import org.cryptoworkshop.ximix.node.XimixNode;
import org.cryptoworkshop.ximix.node.XimixNodeBuilder;
import org.cryptoworkshop.ximix.node.XimixNodeContext;
import org.cryptoworkshop.ximix.test.node.ResourceAnchor;
import org.cryptoworkshop.ximix.test.node.TestXimixNodeFactory;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Tests for basic node stopping and starting.
 */
public class TestNodeStartStop
{


    /**
     * Tests that when stop is called the FutureComplete handler is called when the node shuts down completely.
     *
     * @throws Exception
     */
    @org.junit.Test
    public void testNodeStopWithFutureHandler()
        throws Exception
    {

        XimixNodeBuilder builder = new XimixNodeBuilder(ResourceAnchor.load("/conf/mixnet.xml")).withThrowableHandler(new ThrowableHandler()
        {
            @Override
            public void handle(Throwable throwable)
            {
                throwable.printStackTrace();
            }
        });

       final XimixNode node = builder.build(ResourceAnchor.load("/conf/node1.xml"));


        Thread th = new Thread(new Runnable()
        {
            @Override
            public void run()
            {
                node.start();
            }
        });
        th.setPriority(Thread.MIN_PRIORITY);
        th.start();

        Thread.sleep(1000);
        TestCase.assertTrue(node.shutdown(15, TimeUnit.SECONDS));
    }



}
