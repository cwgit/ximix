package org.cryptoworkshop.ximix.client;

import java.util.Collections;
import java.util.Map;

/**
 * General carrier for statistical data about a node.
 */
public class StatisticsData
{
    private final Map<String, Object> data;

    public StatisticsData(Map<String, Object> data)
    {
        this.data = Collections.unmodifiableMap(data);
    }

    public Map<String, Object> getDataMap()
    {
        return data;
    }
}
