package org.cryptoworkshop.ximix.test.tests;

import junit.framework.TestCase;
import org.cryptoworkshop.ximix.common.util.ExtendedFuture;
import org.cryptoworkshop.ximix.common.util.FutureComplete;
import org.cryptoworkshop.ximix.node.ThrowableHandler;
import org.cryptoworkshop.ximix.node.XimixNode;
import org.cryptoworkshop.ximix.node.XimixNodeContext;
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
    public void testNodeStopWithFutureHandler() throws Exception
    {
       final  XimixNode node = TestXimixNodeFactory.createNode("/conf/mixnet.xml", "/conf/node1.xml", new ThrowableHandler()
        {
            @Override
            public boolean throwable(Throwable throwable)
            {
                throwable.printStackTrace();
                return false;
            }
        });

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

        final AtomicBoolean res = new AtomicBoolean(false);

        ExtendedFuture future = node.stop(10, TimeUnit.SECONDS, new FutureComplete()
        {
            @Override
            public void handle(ExtendedFuture future)
            {
                res.set(true);
            }
        });

        future.await();

        if (!res.get())
        {
            TestCase.fail("Future callback for shutdown was not called.");
        }

        TestCase.assertTrue("Future is done.", future.isDone());

    }

    /**
     * Tests shutdown without a future handler.
     *
     * @throws Exception
     */
    @org.junit.Test
    public void testNodeStopWithFuture() throws Exception
    {
        final XimixNode node = TestXimixNodeFactory.createNode("/conf/mixnet.xml", "/conf/node1.xml", new ThrowableHandler()
        {
            @Override
            public boolean throwable(Throwable throwable)
            {
                throwable.printStackTrace();
                return false;
            }
        });

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


        ExtendedFuture<XimixNodeContext> future = node.stop(10, TimeUnit.SECONDS, null);

        future.await();


        TestCase.assertTrue("Future is done.", future.isDone());

    }


}
