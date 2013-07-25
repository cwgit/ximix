package org.cryptoworkshop.ximix.common.statistics;

import java.util.HashMap;

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
}
