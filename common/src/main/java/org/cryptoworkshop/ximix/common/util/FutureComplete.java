package org.cryptoworkshop.ximix.common.util;

/**
 * Generic handler for callbacks that return values.
 */
public interface FutureComplete<T>
{
    public void handle(ExtendedFuture<T> future);
}
