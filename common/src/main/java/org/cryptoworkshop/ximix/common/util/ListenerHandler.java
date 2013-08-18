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

import java.lang.reflect.InvocationHandler;

/**
 * The basic interface for a ListenerHandler.
 *
 * @param <T> the type of the interface notifications messages are passed to.
 */
public interface ListenerHandler<T>
    extends InvocationHandler
{
    /**
     * Return a notifier we can invoke.
     *
     * @return the notifier encapsulating any added listeners.
     */
    T  getNotifier();

    /**
     * Add a listener to this handler.
     *
     * @param listener the listener to be added.
     */
    void addListener(T listener);

    /**
     * Remove a listener from this handler.
     *
     * @param listener the listener to be removed.
     */
    void removeListener(T listener);
}
