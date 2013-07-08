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
package org.cryptoworkshop.ximix.crypto.util;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class ShareMap<K, V>
{
    private final Map<K, CountDownLatch> latchMap = new HashMap<>();
    private final Map<K, Share<V>> sharedMap = new HashMap<>();
    private final ScheduledExecutorService executor;

    public ShareMap(ScheduledExecutorService executor)
    {
        this.executor = executor;
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
                    latchMap.get(id).countDown();
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
