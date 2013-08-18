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

/**
 * Template interface for a listener handler factory.
 */
public interface ListenerHandlerFactory
{
    /**
     * Create a handler for the passed in listenerClass.
     *
     * @param listenerClass  the interface that notifications are sent on.
     * @param <T> the type of the interface notifies are called on.
     * @return a ListenerHandler.
     */
    <T> ListenerHandler<T> createHandler(Class<T> listenerClass);
}
