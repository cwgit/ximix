package org.cryptoworkshop.ximix.common.test;

import junit.framework.TestCase;
import org.cryptoworkshop.ximix.common.statistics.CrossSection;
import org.cryptoworkshop.ximix.common.statistics.DefaultStatisticsCollector;
import org.junit.Test;

import java.util.concurrent.TimeUnit;

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

}
