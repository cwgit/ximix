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
package org.cryptoworkshop.ximix.common.util;

import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Base class for an operation, used to provide an operation number and an anchor point for listeners.
 *
 * @param <T> the type of the operation listener this operation will accept.
 */
public class Operation<T extends OperationListener>
{
    private static final AtomicLong  operationCounter = new AtomicLong(System.currentTimeMillis());

    protected final T notifier;
    protected final long operationNumber;

    private final ListenerHandler<T> handler;

    /**
     * Base constructor.
     *
     * @param decoupler the executor to decouple listener calls on.
     * @param eventNotifier the notifier to log errors, warnings, and debug statements with.
     * @param listenerClass the interface that our listeners follow.
     */
    protected Operation(Executor decoupler, EventNotifier eventNotifier, Class<T> listenerClass)
    {
        handler = new DecoupledListenerHandlerFactory(decoupler, eventNotifier).createHandler(listenerClass);

        this.operationNumber = operationCounter.getAndIncrement();
        this.notifier = handler.getNotifier();
    }

    /**
     * Return the unique number associated with this operation.
     *
     * @return the operation number.
     */
    public long getOperationNumber()
    {
        return operationNumber;
    }

    /**
     * Add a listener to the operation.
     *
     * @param listener the type of the listener to be added.
     */
    public void addListener(T listener)
    {
        handler.addListener(listener);
    }

    /**
     * Remove a listener from this operation.
     *
     * @param listener the listener to be removed.
     */
    public void removeListener(T listener)
    {
        handler.removeListener(listener);
    }
}
