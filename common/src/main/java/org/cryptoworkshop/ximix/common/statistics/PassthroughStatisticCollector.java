package org.cryptoworkshop.ximix.common.statistics;

import java.util.concurrent.TimeUnit;

/**
 *
 */
public class PassthroughStatisticCollector
    implements StatisticCollector
{

    StatisticCollector impl = null;

    @Override
    public void increment(String name)
    {
        if (impl != null)
        {
            impl.increment(name);
        }
    }

    @Override
    public void decrement(String name)
    {
        if (impl != null)
        {
            impl.decrement(name);
        }
    }

    @Override
    public void record(String name, Object message)
    {
        if (impl != null)
        {
            impl.record(name, message);
        }
    }

    @Override
    public int getCrossSectionCount()
    {

        if (impl != null)
        {
            return impl.getCrossSectionCount();
        }
        return 0;
    }

    @Override
    public CrossSection pollOldestCrossSection(boolean firstNotEmpty)
    {
        if (impl != null)
        {
            return impl.pollOldestCrossSection(firstNotEmpty);
        }

        return null;
    }

    @Override
    public Runnable periodicRunnable()
    {
        if (impl != null)
        {
            return impl.periodicRunnable();
        }
        return null;
    }

    @Override
    public boolean stop(TimeUnit timeUnit, int duration)
    {
        if (impl != null)
        {
            return impl.stop(timeUnit, duration);
        }

        return true;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public void timeStart(String name)
    {
        if (impl != null)
        {
            impl.timeStart(name);
        }
    }

    @Override
    public Long timeEnd(String name)
    {
        if (impl != null)
        {
            return impl.timeEnd(name);
        }
        return null;
    }

    @Override
    public Long recordEnd(String name)
    {
        if (impl != null)
        {
            return impl.recordEnd(name);
        }
        return null;
    }

    @Override
    public void start()
    {
        if (impl != null)
        {
            impl.start();
        }
    }

    public void setImpl(StatisticCollector impl)
    {
        this.impl = impl;
    }
}
