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
import java.util.ArrayList;
import java.util.List;

public class ListenerHandlerFactory
{
    private final List listeners = new ArrayList();

    public ListenerHandlerFactory()
    {

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
                    try
                    {
                        method.invoke(listener, objects);
                    }
                    catch (Exception e)
                    {
                        e.printStackTrace();  //TODO: but needs to be logged somewhere!
                    }

                }
            }

            return null;
        }

    }
}
