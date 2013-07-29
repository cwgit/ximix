package org.cryptoworkshop.ximix.common.test;

import junit.framework.TestCase;
import org.cryptoworkshop.ximix.common.statistics.CrossSection;
import org.cryptoworkshop.ximix.common.statistics.DefaultStatisticsCollector;
import org.junit.Test;

import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 *
 */
public class StatisticsCollectorTests extends TestCase
{
    @Test
    public void testStartStop()
        throws Exception
    {
        DefaultStatisticsCollector stats = new DefaultStatisticsCollector();
        stats.start();
        TestCase.assertTrue(stats.stop(TimeUnit.SECONDS, 30));
    }

    @Test
    public void testIncrement()
        throws Exception
    {
        DefaultStatisticsCollector stats = new DefaultStatisticsCollector();
        stats.setDurationMillis(5000);
        stats.start();

        stats.increment("foo");
        stats.increment("foo");

        stats.increment("bar");

        Thread.sleep(6000);
        stats.stop(TimeUnit.SECONDS, 6);

        TestCase.assertEquals(2, stats.getCrossSectionCount());
        CrossSection section = stats.pollOldestCrossSection(false);
        TestCase.assertNotNull(section);

        TestCase.assertEquals(2, section.get("foo"));
        TestCase.assertEquals(1, section.get("bar"));

    }

    @Test
    public void testDecrement()
        throws Exception
    {
        DefaultStatisticsCollector stats = new DefaultStatisticsCollector();
        stats.setDurationMillis(5000);
        stats.start();

        stats.decrement("foo");
        stats.decrement("foo");

        stats.decrement("bar");

        Thread.sleep(6000);
        stats.stop(TimeUnit.SECONDS, 6);

        TestCase.assertEquals(2, stats.getCrossSectionCount());
        CrossSection section = stats.pollOldestCrossSection(false);
        TestCase.assertNotNull(section);

        TestCase.assertEquals(-2, section.get("foo"));
        TestCase.assertEquals(-1, section.get("bar"));

    }

    @Test
    public void testRecording()
        throws Exception
    {
        DefaultStatisticsCollector stats = new DefaultStatisticsCollector();
        stats.setDurationMillis(5000);
        stats.start();

        stats.record("foo", 10);
        stats.record("bar", 20);
        stats.record("foo", 30);

        Thread.sleep(6000);
        stats.stop(TimeUnit.SECONDS, 6);

        TestCase.assertEquals(2, stats.getCrossSectionCount());
        CrossSection section = stats.pollOldestCrossSection(false);
        TestCase.assertNotNull(section);

        TestCase.assertEquals(2, section.getAsList("foo", false).size());
        TestCase.assertEquals(1, section.getAsList("bar", false).size());

        TestCase.assertEquals(10, section.getAsList("foo", false).get(0));
        TestCase.assertEquals(30, section.getAsList("foo", false).get(1));

        TestCase.assertEquals(20, section.getAsList("bar", false).get(0));

        TestCase.assertEquals(0, section.getAsList("cats", true).size());

        try
        {
            section.getAsList("cats", false);
            TestCase.fail();
        }
        catch (Exception ex)
        {
            TestCase.assertTrue(true);
        }

    }

    @Test
    public void testTimingFunctions()
        throws Exception
    {
        final DefaultStatisticsCollector stats = new DefaultStatisticsCollector();
        stats.setDurationMillis(5000);
        stats.start();

        final CountDownLatch latch = new CountDownLatch(3);

        Thread th1 = new Thread(new Runnable()
        {
            @Override
            public void run()
            {
                stats.timeStart("th1");
                try
                {
                    Thread.sleep(2000);
                }
                catch (InterruptedException e)
                {
                    e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                }

                stats.timeEnd("th1");

                latch.countDown();
            }
        });

        th1.setPriority(Thread.MIN_PRIORITY);
        th1.start();

        Thread th2 = new Thread(new Runnable()
        {
            @Override
            public void run()
            {
                Random r = new Random();

                for (int t = 0; t < 2; t++)
                {

                    stats.timeStart("th2");
                    try
                    {
                        Thread.sleep(1000 + r.nextInt(500));
                    }
                    catch (InterruptedException e)
                    {
                        e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                    }
                    stats.recordEnd("th2");

                }
                latch.countDown();
            }
        });

        th2.setPriority(Thread.MIN_PRIORITY);
        th2.start();

        Thread.sleep(5000);

        latch.await(5000, TimeUnit.MILLISECONDS);


        CrossSection section = stats.pollOldestCrossSection(false);

        TestCase.assertEquals(2, section.getAsList("th2", false).size());


        //
        // Range testing values may fail if device is interrupted during testing..
        //

        Long v = (Long)section.get("th1");
        TestCase.assertTrue(v >= 2000 && v < 2200);


        v = (Long)section.getAsList("th2", false).get(0);
        TestCase.assertTrue(v >= 1000 && v < 1800);

        v = (Long)section.getAsList("th2", false).get(1);
        TestCase.assertTrue(v >= 1000 && v < 1800);

    }

    @Test
    public void testFailureOnIncorrectThreadRecord()
        throws Exception
    {
        final DefaultStatisticsCollector stats = new DefaultStatisticsCollector();
        stats.setDurationMillis(5000);
        stats.start();

        final CountDownLatch latch = new CountDownLatch(3);

        Thread th1 = new Thread(new Runnable()
        {
            @Override
            public void run()
            {
                stats.timeStart("th1");
                try
                {
                    Thread.sleep(2000);
                }
                catch (InterruptedException e)
                {
                    e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                }

                stats.timeEnd("th1");

                latch.countDown();
            }
        });

        th1.setPriority(Thread.MIN_PRIORITY);
        th1.start();

        final AtomicBoolean recordEndFailedAsExpected = new AtomicBoolean(false);

        Thread th2 = new Thread(new Runnable()
        {
            @Override
            public void run()
            {
                Random r = new Random();

                for (int t = 0; t < 2; t++)
                {

                    stats.timeStart("th2");
                    try
                    {
                        Thread.sleep(1000);
                    }
                    catch (InterruptedException e)
                    {
                        e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                    }
                    try
                    {
                        stats.recordEnd("th1"); // Will cause failure.
                        recordEndFailedAsExpected.set(false);
                    }
                    catch (Exception ex)
                    {
                        recordEndFailedAsExpected.set(true);
                    }
                }
                latch.countDown();
            }
        });

        th2.setPriority(Thread.MIN_PRIORITY);
        th2.start();

        Thread.sleep(5000);

        latch.await(5000, TimeUnit.MILLISECONDS);


        TestCase.assertTrue(recordEndFailedAsExpected.get());


    }



    @Test
    public void testFailureOnIncorrectThreadSimpleEnd()
        throws Exception
    {
        final DefaultStatisticsCollector stats = new DefaultStatisticsCollector();
        stats.setDurationMillis(5000);
        stats.start();

        final CountDownLatch latch = new CountDownLatch(3);

        Thread th1 = new Thread(new Runnable()
        {
            @Override
            public void run()
            {
                stats.timeStart("th1");
                try
                {
                    Thread.sleep(2000);
                }
                catch (InterruptedException e)
                {
                    e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                }

                stats.timeEnd("th1");

                latch.countDown();
            }
        });

        th1.setPriority(Thread.MIN_PRIORITY);
        th1.start();

        final AtomicBoolean recordEndFailedAsExpected = new AtomicBoolean(false);

        Thread th2 = new Thread(new Runnable()
        {
            @Override
            public void run()
            {
                Random r = new Random();

                for (int t = 0; t < 2; t++)
                {

                    stats.timeStart("th2");
                    try
                    {
                        Thread.sleep(1000);
                    }
                    catch (InterruptedException e)
                    {
                        e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                    }
                    try
                    {
                        stats.timeEnd("th1"); // Will cause failure.
                        recordEndFailedAsExpected.set(false);
                    }
                    catch (Exception ex)
                    {
                        recordEndFailedAsExpected.set(true);
                    }
                }
                latch.countDown();
            }
        });

        th2.setPriority(Thread.MIN_PRIORITY);
        th2.start();

        Thread.sleep(5000);

        latch.await(5000, TimeUnit.MILLISECONDS);


        TestCase.assertTrue(recordEndFailedAsExpected.get());


    }



}
