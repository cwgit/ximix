package org.cryptoworkshop.ximix.test.tests;

import java.util.concurrent.atomic.AtomicReference;

import org.junit.Assert;

public class TestUtil
{

    static void checkThread(AtomicReference threadHolder)
    {
        Object thread;

        if ((thread = threadHolder.getAndSet(Thread.currentThread())) != null)
        {
            Assert.assertEquals(thread, Thread.currentThread());
        }
    }
}
