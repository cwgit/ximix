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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;

public class DecoupledListenerHandlerFactory
    implements ListenerHandlerFactory
{
    private final Executor decoupler;
    private final List listeners = new ArrayList();

    public DecoupledListenerHandlerFactory(Executor decoupler)
    {
        this.decoupler = decoupler;
    }

    public <T> ListenerHandler<T> createHandler(Class<T> listenerClass)
    {
        return new Handler<T>(listenerClass);
    }

    private class Handler<T>
        implements ListenerHandler<T>
    {
        private final Class<T> listenerClass;

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
                catch (IllegalAccessException e)
                {
                    e.printStackTrace();  //TODO: this should never happen, but needs to be logged somewhere!
                }
                catch (InvocationTargetException e)
                {
                    e.printStackTrace();  //TODO: this should never happen, but needs to be logged somewhere!
                }
            }
        }
    }
}
