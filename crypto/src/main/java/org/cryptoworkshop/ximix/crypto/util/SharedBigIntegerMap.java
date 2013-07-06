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

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class SharedBigIntegerMap<T>
{
    private final Map<T, CountDownLatch> latchMap = new HashMap<>();
    private final Map<T, BigInteger> sharedMap = new HashMap<>();
    private final ScheduledExecutorService executor;

    public SharedBigIntegerMap(ScheduledExecutorService executor)
    {
        this.executor = executor;
    }

    public void init(T id, int numberOfParties)
    {
        synchronized (this)
        {
            latchMap.put(id, new CountDownLatch(numberOfParties));
        }
    }

    public boolean containsKey(T id)
    {
        synchronized (this)
        {
            return latchMap.containsKey(id);
        }
    }

    public void waitFor(T id)
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

    public void addValue(T id, BigInteger value)
    {
         executor.execute(new AddTask(id, value));
    }

    public BigInteger getValue(T id)
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

    public BigInteger getValue(T id, long timeout, TimeUnit timeUnit)
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
        private final T id;
        private final BigInteger value;

        AddTask(T id, BigInteger value)
        {

            this.id = id;
            this.value = value;
        }

        @Override
        public void run()
        {
            synchronized (SharedBigIntegerMap.this)
            {
                // other values may have arrived before we get a message
                // starting the process.
                if (latchMap.containsKey(id))
                {
                    if (sharedMap.containsKey(id))
                    {
                        sharedMap.put(id, sharedMap.get(id).add(value));
                    }
                    else
                    {
                        sharedMap.put(id, value);
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
