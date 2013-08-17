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
package org.cryptoworkshop.ximix.node.crypto.util;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.cryptoworkshop.ximix.common.util.DecoupledListenerHandlerFactory;
import org.cryptoworkshop.ximix.common.util.ListenerHandler;

public class ShareMap<K, V>
{
    private final Map<K, CountDownLatch> latchMap = new HashMap<>();
    private final Map<K, Share<V>> sharedMap = new HashMap<>();
    private final ScheduledExecutorService executor;
    private final ListenerHandler<ShareMapListener> listenerHandler;
    private final ShareMapListener notifier;

    public ShareMap(ScheduledExecutorService executor, Executor decoupler)
    {
        this.executor = executor;

        this.listenerHandler = new DecoupledListenerHandlerFactory(decoupler).createHandler(ShareMapListener.class);
        this.notifier = listenerHandler.getNotifier();
    }

    public void init(K id, int numberOfParties)
    {
        synchronized (this)
        {
            latchMap.put(id, new CountDownLatch(numberOfParties));
        }
    }

    public boolean containsKey(K id)
    {
        synchronized (this)
        {
            return latchMap.containsKey(id);
        }
    }

    public void waitFor(K id)
    {
        CountDownLatch latch;
        synchronized (this)
        {
            latch = latchMap.get(id);
        }
        try
        {
            latch.await();
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
        }
    }

    public void addValue(K id, Share<V> value)
    {
         executor.execute(new AddTask(id, value));
    }

    public void addListener(ShareMapListener<K, V> listener)
    {
        listenerHandler.addListener(listener);
    }

    public Share<V> getShare(K id)
    {
        try
        {
            CountDownLatch latch;
            synchronized (this)
            {
                latch = latchMap.get(id);
            }

            latch.await();
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
        }

        synchronized (this)
        {
            return sharedMap.get(id);
        }
    }

    public Share<V> getShare(K id, long timeout, TimeUnit timeUnit)
    {
        try
        {
            CountDownLatch latch;
            synchronized (this)
            {
                latch = latchMap.get(id);
            }

            if (latch.await(timeout, timeUnit))
            {
                synchronized (this)
                {
                    return sharedMap.get(id);
                }
            }
            else
            {
                // TODO:
                return null;
            }
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    public Set<K> getIDs()
    {
        return sharedMap.keySet();
    }

    private class AddTask
        implements Runnable
    {
        private final K id;
        private final Share<V> share;

        AddTask(K id, Share<V> share)
        {
            this.id = id;
            this.share = share;
        }

        @Override
        public void run()
        {
            synchronized (ShareMap.this)
            {
                // other values may have arrived before we get a message
                // starting the process.
                if (latchMap.containsKey(id))
                {
                    if (sharedMap.containsKey(id))
                    {
                        sharedMap.put(id, sharedMap.get(id).add(share));
                    }
                    else
                    {
                        sharedMap.put(id, share);
                    }
                    CountDownLatch latch = latchMap.get(id);
                    latch.countDown();
                    if (latch.getCount() == 0)
                    {
                        notifier.shareCompleted(ShareMap.this, id);
                    }
                }
                else
                {
                    // TODO: set some sort of expiry
                    executor.execute(this);
                }
            }
        }
    }
}
