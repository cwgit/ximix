package org.cryptoworkshop.ximix.test.node;

import org.cryptoworkshop.ximix.common.util.EventNotifier;

/**
 *
 */
public class TestNotifier implements EventNotifier
{


    @Override
    public void notify(Level level, Throwable throwable)
    {
        System.err.println(level);
        throwable.printStackTrace(System.err);
    }

    @Override
    public void notify(Level level, Object detail)
    {
        System.err.println(level + ": " + detail);
    }

    @Override
    public void notify(Level level, Object detail, Throwable throwable)
    {
        System.err.println(level + ": " + detail);
        throwable.printStackTrace(System.err);
    }
}
