package org.cryptoworkshop.ximix.mixnet.admin;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;

/**
 *   By way of example..
 */
public class NodeHealth {

    private final long freeMemory;
    private final long totalMemory;
    private int availableProcessors = 0;
    private long uptime = 0;

    public NodeHealth() {
        availableProcessors = Runtime.getRuntime().availableProcessors();
        freeMemory = Runtime.getRuntime().freeMemory();
        totalMemory = Runtime.getRuntime().totalMemory();
        RuntimeMXBean mxbean = ManagementFactory.getRuntimeMXBean();
        mxbean.getUptime();
    }

    public long getFreeMemory() {
        return freeMemory;
    }

    public long getTotalMemory() {
        return totalMemory;
    }

    public int getAvailableProcessors() {
        return availableProcessors;
    }

    public void setAvailableProcessors(int availableProcessors) {
        this.availableProcessors = availableProcessors;
    }

    public long getUptime() {
        return uptime;
    }

    public void setUptime(long uptime) {
        this.uptime = uptime;
    }
}
