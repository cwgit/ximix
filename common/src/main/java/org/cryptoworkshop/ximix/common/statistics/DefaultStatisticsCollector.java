package org.cryptoworkshop.ximix.common.statistics;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 *
 */
public class DefaultStatisticsCollector
    implements StatisticCollector
{

    private List<CrossSection> crossSections = new ArrayList<>();
    private int durationMillis = 60000;
    private Runnable periodicRunnable = null;
    private Map<String, Object> initValues = new HashMap<>();
    private Thread rollOverThread = null;
    private AtomicBoolean exitFlag = new AtomicBoolean(false);
    private CountDownLatch stopLatch = null;
    private int maxCrossSectionAge = 3600000; // 1 hour.
    private int maxTotalCrossSections = 3600;

    public DefaultStatisticsCollector()
    {
        periodicRunnable = new Runnable()
        {
            @Override
            public void run()
            {
                closeCrossSection();
            }
        };
    }

    @Override
    public synchronized void start()
    {
        if (rollOverThread == null)
        {
            rollOverThread = new Thread(new Runnable()
            {
                @Override
                public void run()
                {
                    while (!exitFlag.get())
                    {

                        closeCrossSection();
                        try
                        {
                            Thread.sleep(durationMillis);
                        }
                        catch (InterruptedException e)
                        {
                            // Deliberately ignored.
                        }
                    }


                    if (stopLatch != null)
                    {
                        stopLatch.countDown();
                    }
                }
            });

            rollOverThread.setPriority(Thread.MIN_PRIORITY);
            rollOverThread.setDaemon(true);
            rollOverThread.start();
        }
    }

    @Override
    public synchronized boolean stop(TimeUnit timeUnit, int duration)
    {
        if (rollOverThread != null && rollOverThread.isAlive())
        {
            stopLatch = new CountDownLatch(1);
            exitFlag.set(true);
            try
            {
                rollOverThread.interrupt();
            }
            catch (Exception ex)
            {
                // Deliberately ignored.
            }

            try
            {
                return stopLatch.await(duration, timeUnit);
            }
            catch (InterruptedException e)
            {
                // Deliberately ignored.
            }
        }

        return true;
    }

    public void closeCrossSection()
    {
        synchronized (crossSections)
        {
            closeCrossSectionNoSync();
        }
    }

    private void closeCrossSectionNoSync()
    {
        CrossSection newOne = new CrossSection(System.currentTimeMillis(), durationMillis);
        newOne.putAll(initValues);
        crossSections.add(newOne);


        //
        // Remove old cross sections.
        //
        int t = crossSections.size();
        long max = System.currentTimeMillis() - maxCrossSectionAge;
        while (--t >= 1)
        {
            if (t > maxTotalCrossSections)
            {
                crossSections.remove(t);
                continue;
            }

            if (crossSections.get(t).getStartTime() < max)
            {
                crossSections.remove(t);
            }
        }


    }

    @Override
    public int getCrossectionCount()
    {
        synchronized (crossSections)
        {
            return crossSections.size();
        }
    }

    @Override
    public CrossSection pollOldestCrossSection()
    {
        synchronized (crossSections)
        {
            if (crossSections.size() > 1)
            {
                return crossSections.remove(0);
            }
            else if (!crossSections.isEmpty())
            {
                //
                // Copy current
                //
                return new CrossSection(crossSections.get(0));
            }

            return null;

        }


    }

    @Override
    public Runnable periodicRunnable()
    {
        return periodicRunnable;
    }

    @Override
    public void increment(String name)
    {
        synchronized (crossSections)
        {
            if (crossSections.isEmpty())
            {
                closeCrossSectionNoSync();
            }

            CrossSection s = crossSections.get(crossSections.size() - 1);
            if (s.containsKey(name))
            {
                Integer i = (Integer)s.get(name);
                if (i == null)
                {
                    i = new Integer(0);
                    s.put(name, i);
                }
                else
                {
                    s.put(name, i + 1);
                }
            }
        }
    }

    @Override
    public void decrement(String name)
    {
        synchronized (crossSections)
        {
            if (crossSections.isEmpty())
            {
                closeCrossSectionNoSync();
            }

            CrossSection s = crossSections.get(crossSections.size() - 1);
            if (s.containsKey(name))
            {
                Integer i = (Integer)s.get(name);
                if (i == null)
                {
                    i = new Integer(0);
                    s.put(name, i);
                }
                else
                {

                    s.put(name, i - 1);
                }
            }
        }
    }

    @Override
    public void log(String name, Object value)
    {

        synchronized (crossSections)
        {
            CrossSection s = crossSections.get(crossSections.size() - 1);
            if (s.containsKey(name))
            {
                List i = (List)s.get(name);
                if (i == null)
                {
                    i = new ArrayList();

                    s.put(name, i);
                }
                i.add(value);
            }
        }
    }

    public int getDurationMillis()
    {
        return durationMillis;
    }

    public void setDurationMillis(int durationMillis)
    {
        boolean interrupt = durationMillis < this.durationMillis;

        this.durationMillis = durationMillis;

        if (interrupt)
        {
            try
            {
                rollOverThread.interrupt();
            }
            catch (Exception ex)
            {
                // Deliberately ignored.
            }
        }

    }

    public void trim(int count)
    {
        if (count < 1)
        {
            count = 1;
        }

        synchronized (crossSections)
        {
            while (crossSections.size() > count)
            {
                crossSections.remove(crossSections.size() - 1);
            }
        }

    }

    public Map<String, Object> getInitValues()
    {
        return initValues;
    }
}
