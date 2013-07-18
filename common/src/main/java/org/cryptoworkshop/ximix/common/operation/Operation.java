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
package org.cryptoworkshop.ximix.common.operation;

import java.util.concurrent.Executor;

import org.cryptoworkshop.ximix.common.util.DecoupledListenerHandlerFactory;
import org.cryptoworkshop.ximix.common.util.ListenerHandler;

public class Operation<T extends OperationListener>
{
    protected final T notifier;
    private final ListenerHandler<T> handler;

    protected Operation(Executor decoupler, Class listenerClass)
    {
        handler = new DecoupledListenerHandlerFactory(decoupler).createHandler(listenerClass);

        this.notifier = handler.getNotifier();
    }

    public void addListener(T listener)
    {
        handler.addListener(listener);
    }
}
