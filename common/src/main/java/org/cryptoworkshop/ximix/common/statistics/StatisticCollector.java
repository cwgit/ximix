package org.cryptoworkshop.ximix.common.statistics;

import java.util.concurrent.TimeUnit;

/**
 *
 */
public interface StatisticCollector
{
    void increment(String name);
    void decrement(String name);
    void record(String name, Object message);
    int getCrossSectionCount();
    CrossSection pollOldestCrossSection(boolean firstNotEmpty);
    Runnable periodicRunnable();
    boolean stop(TimeUnit timeUnit, int duration);

    void timeStart(String name);
    Long timeEnd(String name);


    void start();
}
