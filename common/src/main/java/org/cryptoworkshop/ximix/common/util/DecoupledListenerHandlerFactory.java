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

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Executor;

/**
 * Factory class for creating decoupled listener handlers.
 */
public class DecoupledListenerHandlerFactory
    implements ListenerHandlerFactory
{
    private final Executor decoupler;
    private final EventNotifier eventNotifier;

    /**
     * Base constructor - set the decoupler.
     *
     * @param decoupler  the executor listener calls are to be decoupled on.
     * @param eventNotifier the notifier to log errors, warnings, and debug statements with.
     */
    public DecoupledListenerHandlerFactory(Executor decoupler, EventNotifier eventNotifier)
    {
        this.decoupler = decoupler;
        this.eventNotifier = eventNotifier;
    }

    /**
     * Create a decoupling handler for the passed in listenerClass.
     *
     * @param listenerClass  the interface that notifications are sent on.
     * @param <T> the type of the interface notifies are called on.
     * @return a ListenerHandler.
     */
    public <T> ListenerHandler<T> createHandler(Class<T> listenerClass)
    {
        return new Handler<>(listenerClass);
    }

    private class Handler<T>
        implements ListenerHandler<T>
    {
        private final Class<T> listenerClass;
        private final Set<T> listeners = new HashSet<>();

        public Handler(Class<T> listenerClass)
        {
            this.listenerClass = listenerClass;
        }

        @Override
        public void addListener(T listener)
        {
            synchronized (listeners)
            {
                listeners.add(listener);
            }
        }

        @Override
        public void removeListener(T listener)
        {
            synchronized (listeners)
            {
                listeners.remove(listener);
            }
        }

        @Override
        public T getNotifier()
        {
            return (T)Proxy.newProxyInstance(this.getClass().getClassLoader(), new Class[]{listenerClass}, this);
        }

        @Override
        public Collection<T> listeners()
        {
            synchronized (listeners)
            {
                return new HashSet<>(listeners);
            }
        }

        @Override
        public Object invoke(final Object o, final Method method, final Object[] objects)
            throws Throwable
        {
            synchronized (listeners)
            {
                for (Object listener : listeners)
                {
                    decoupler.execute(new ObjectTask(listener, method, objects));
                }
            }

            return null;
        }

        private class ObjectTask
            implements Runnable
        {
            private final Object o;
            private final Method method;
            private final Object[] objects;

            public ObjectTask(Object o, Method method, Object[] objects)
            {
                this.o = o;
                this.method = method;
                this.objects = objects;
            }

            @Override
            public void run()
            {
                try
                {
                    method.invoke(o, objects);
                }
                catch (Exception e)
                {
                    eventNotifier.notify(EventNotifier.Level.ERROR, "Exception in decoupled listener handler: " + e.getMessage(), e);
                }
            }
        }
    }
}
