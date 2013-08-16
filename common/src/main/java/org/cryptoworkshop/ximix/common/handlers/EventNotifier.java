package org.cryptoworkshop.ximix.common.handlers;

/**
 *
 */
public interface EventNotifier
{
    public static enum Level
    {
        DEBUG, INFO, WARN, ERROR
    }

    /**
     * Notify of a throwable.
     *
     * @param level
     * @param throwable The throwable.
     */
    void notify(Level level, Throwable throwable);

    void notify(Level level, Object detail);

    void notify(Level level, Object detail, Throwable throwable);
}
