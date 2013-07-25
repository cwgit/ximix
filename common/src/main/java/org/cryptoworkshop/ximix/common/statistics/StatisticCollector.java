package org.cryptoworkshop.ximix.common.statistics;

import java.util.concurrent.TimeUnit;

/**
 *
 */
public interface StatisticCollector
{
    void increment(String name);
    void decrement(String name);
    void log(String name, Object message);
    int getCrossectionCount();
    CrossSection pollOldestCrossSection();
    Runnable periodicRunnable();

    boolean stop(TimeUnit timeUnit, int duration);

    void start();
}
