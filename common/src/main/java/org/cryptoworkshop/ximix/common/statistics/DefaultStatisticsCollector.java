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

    protected List<CrossSection> crossSections = new ArrayList<>();
    protected CrossSection currentSection = new CrossSection();
    protected int durationMillis = 60000;
    protected Runnable periodicRunnable = null;
    protected AtomicBoolean exitFlag = new AtomicBoolean(false);
    protected CountDownLatch stopLatch = null;
    protected int maxCrossSectionAge = 3600000; // 1 hour.
    protected int maxTotalCrossSections = 3600;
    protected Map<Thread, Map<String, Long>> timingMap = new HashMap<>();
    private Map<String, Object> initValues = new HashMap<>();
    private Thread rollOverThread = null;


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


                        try
                        {
                            Thread.sleep(durationMillis);
                        }
                        catch (InterruptedException e)
                        {
                            //                           System.out.println();
                            // Deliberately ignored.
                        }
                        closeCrossSection();
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

    @Override
    public void timeStart(String name)
    {
        synchronized (timingMap)
        {
            if (timingMap.containsKey(Thread.currentThread()))
            {
                timingMap.get(Thread.currentThread()).put(name, System.currentTimeMillis());
            }
            else
            {
                HashMap<String, Long> m = new HashMap<>();
                m.put(name, System.currentTimeMillis());
                timingMap.put(Thread.currentThread(), m);
            }
        }
    }

    @Override
    public Long timeEnd(String name)
    {
        synchronized (timingMap)
        {
            Map<String, Long> m = timingMap.get(Thread.currentThread());
            if (m != null)
            {
                Long l = m.remove(name);

                if (m.isEmpty())
                {
                    timingMap.remove(Thread.currentThread());
                }

                if (l != null)
                {
                    return System.currentTimeMillis() - l;
                }
            }
        }
        return null;
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

        CrossSection old = currentSection;

        synchronized (currentSection)
        {
            currentSection = new CrossSection();
        }

        synchronized (crossSections)
        {
            crossSections.add(old);

            //
            // Remove old cross sections that exceed lifespan or total count.
            //
            int t = crossSections.size();
            long min = System.currentTimeMillis() - maxCrossSectionAge;

            //
            // by size.
            //
            while (crossSections.size() > maxTotalCrossSections)
            {
                crossSections.remove(0);
            }

            //
            // By age..
            //

            for (t = 0; t < crossSections.size() - 1 && crossSections.get(t).getStartTime() < min; t++)
            {
                t = 0;
                crossSections.remove(0);
            }


        }
    }

    @Override
    public int getCrossSectionCount()
    {
        synchronized (crossSections)
        {
            return crossSections.size();
        }
    }

    @Override
    public CrossSection pollOldestCrossSection(boolean firstNotEmpty)
    {
        synchronized (crossSections)
        {

            while (!crossSections.isEmpty())
            {
                CrossSection sec = crossSections.remove(0);
                if (firstNotEmpty && sec.isEmpty())
                {
                    continue;
                }
                else
                {
                    return sec;
                }
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
        synchronized (currentSection)
        {
            Integer i = (Integer)currentSection.get(name);
            if (i == null)
            {
                i = new Integer(1);
                currentSection.put(name, i);
            }
            else
            {
                currentSection.put(name, i + 1);
            }

        }
    }

    @Override
    public void decrement(String name)
    {
        synchronized (currentSection)
        {
            Integer i = (Integer)currentSection.get(name);
            if (i == null)
            {
                i = new Integer(-1);
                currentSection.put(name, i);
            }
            else
            {
                currentSection.put(name, i - 1);
            }
        }

    }

    @Override
    public void record(String name, Object value)
    {
        synchronized (currentSection)
        {
            List i = (List)currentSection.get(name);
            if (i == null)
            {
                i = new ArrayList();
                currentSection.put(name, i);
            }
            i.add(value);
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
