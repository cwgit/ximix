package org.cryptoworkshop.ximix.test.tests;

import junit.framework.TestCase;
import org.cryptoworkshop.ximix.node.XimixNode;
import org.cryptoworkshop.ximix.test.node.NodeTestUtil;

import java.util.concurrent.TimeUnit;

/**
 * Tests for basic node stopping and starting.
 */
public class NodeStartStopTest
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

        final XimixNode node = NodeTestUtil.getXimixNode("/conf/mixnet.xml", "/conf/node1.xml");


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
