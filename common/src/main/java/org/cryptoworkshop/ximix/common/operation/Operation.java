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

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;

public class Operation<T extends OperationListener>
{
    protected final T notifier;
    private final NotifierHandler handler;

    protected Operation(Executor decoupler, Class listenerClass)
    {
        handler = new NotifierHandler(decoupler);

        this.notifier = (T)Proxy.newProxyInstance(this.getClass().getClassLoader(), new Class[]{listenerClass}, handler);
    }

    public void addListener(T listener)
    {
        handler.addListener(listener);
    }

    private class NotifierHandler
        implements InvocationHandler
    {
        private final Executor decoupler;
        private final List listeners = new ArrayList();

        public NotifierHandler(Executor decoupler)
        {
            this.decoupler = decoupler;
        }

        void addListener(T listener)
        {
            synchronized (listeners)
            {
                listeners.add(listener);
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
