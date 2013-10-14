package org.cryptoworkshop.ximix.common.util;

/**
 * Standard interface for an event notifier implementation.
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
     * @param level the level this event is at.
     * @param throwable the throwable causing the event.
     */
    void notify(Level level, Throwable throwable);

    /**
     * General notification with a detail object,
     *
     * @param level the level this event is at.
     * @param detail the detail associated with this event notification.
     */
    void notify(Level level, Object detail);

    /**
     *
     * @param level the level this event is at.
     * @param detail the detail associated with this event notification.
     * @param throwable the throwable causing the event.
     */
    void notify(Level level, Object detail, Throwable throwable);
}
