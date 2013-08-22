package org.cryptoworkshop.ximix.client;

import java.util.Collections;
import java.util.Map;

/**
 * General carrier for status information about a node.
 */
public class FullInfoData
{
    private final Map<String, Object> data;

    public FullInfoData(Map<String, Object> data)
    {
        this.data = Collections.unmodifiableMap(data);
    }

    public Map<String, Object> getDataMap()
    {
        return data;
    }
}
