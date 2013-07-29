package org.cryptoworkshop.ximix.common.statistics;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;

/**
 *
 */
public class CrossSection extends HashMap<String, Object>
{
    long startTime = System.currentTimeMillis();
    int duration = 10;

    public CrossSection()
    {
        super();
    }

    public CrossSection(CrossSection c)
    {
        this.duration = c.duration;
        this.startTime = c.startTime;
        putAll(c);
    }


    public CrossSection(long startTime, int duration)
    {
        this.duration = duration;
        this.startTime = startTime;
    }

    public Object get(String name, Object def)
    {
        if (!containsKey(name))
        {
            return def;
        }
        return get(name);
    }

    public long getStartTime()
    {
        return startTime;
    }

    public void setStartTime(long startTime)
    {
        this.startTime = startTime;
    }

    public int getDuration()
    {
        return duration;
    }

    public void setDuration(int duration)
    {
        this.duration = duration;
    }

    public List getAsList(String foo, boolean returnEmpty)
    {
        Object o = get(foo);
        if (o != null && o instanceof List)
        {
            return (List)o;
        }
        else if (returnEmpty)
        {
            return Collections.EMPTY_LIST;
        }

        throw new IllegalArgumentException(foo + " cannot be assigned to a List, it is " + o.getClass());
    }
}
