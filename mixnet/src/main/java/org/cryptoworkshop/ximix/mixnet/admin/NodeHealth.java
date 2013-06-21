/**
 * Copyright 2013 Crypto Workshop Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cryptoworkshop.ximix.mixnet.admin;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;

/**
 * By way of example..
 */
public class NodeHealth
{

    private final long freeMemory;
    private final long totalMemory;
    private int availableProcessors = 0;
    private long uptime = 0;

    public NodeHealth()
    {
        availableProcessors = Runtime.getRuntime().availableProcessors();
        freeMemory = Runtime.getRuntime().freeMemory();
        totalMemory = Runtime.getRuntime().totalMemory();
        RuntimeMXBean mxbean = ManagementFactory.getRuntimeMXBean();
        mxbean.getUptime();
    }

    public long getFreeMemory()
    {
        return freeMemory;
    }

    public long getTotalMemory()
    {
        return totalMemory;
    }

    public int getAvailableProcessors()
    {
        return availableProcessors;
    }

    public void setAvailableProcessors(int availableProcessors)
    {
        this.availableProcessors = availableProcessors;
    }

    public long getUptime()
    {
        return uptime;
    }

    public void setUptime(long uptime)
    {
        this.uptime = uptime;
    }
}
