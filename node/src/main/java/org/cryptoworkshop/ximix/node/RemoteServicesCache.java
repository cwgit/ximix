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
package org.cryptoworkshop.ximix.node;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.cryptoworkshop.ximix.common.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.NodeInfo;
import org.cryptoworkshop.ximix.common.message.RequestCapabilities;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.Service;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.mixnet.service.RemoteBoardHostingService;

public class RemoteServicesCache
{
    private static final int TIME_OUT = 2;

    private final NodeContext    nodeContext;

    private final ExecutorService threadPool = Executors.newCachedThreadPool();

    private final Map<NodeEntry, Future<NodeInfo>> cache = new HashMap<>();
    private final Map<NodeEntry, Boolean> active = new HashMap<>();
    private final ScheduledExecutorService scheduler;

    public RemoteServicesCache(NodeContext nodeContext)
    {
        this.nodeContext = nodeContext;
        this.scheduler = nodeContext.getScheduledExecutor();
    }

    private synchronized void checkEntry(final NodeEntry entry)
    {
        if (!active.containsKey(entry))
        {
            Future<NodeInfo> future = cache.get(entry);

            if (future != null && future.isDone())
            {
                invalidateEntry(entry);
            }
            else
            {
                scheduleEntryCheck(entry);
            }
        }
        else
        {
            scheduleCollectionRenewal(entry);
        }
    }


    private synchronized void invalidateEntry(NodeEntry entry)
    {
        Future<NodeInfo> future = cache.remove(entry);
        if (future != null)
        {
            future.cancel(true);
        }
        else     // put back queries that are still in progress to allow for short term caching.
        {
            cache.put(entry, future);
        }
    }

    private synchronized void scheduleCollectionRenewal(final NodeEntry entry)
    {
        Callable<NodeInfo> task = makeCallable(entry.getName());

        final Future<NodeInfo> future = threadPool.submit(task);

        Runnable makeCurrentTask = new Runnable()
        {
            @Override
            public void run()
            {
                synchronized (RemoteServicesCache.this)
                {
                    cache.put(entry, future);
                    active.remove(entry);
                }

                scheduleEntryCheck(entry);
            }
        };

        // we give the future 1 second to resolve before overwriting the existing cache entry with it.
        scheduler.schedule(makeCurrentTask, 1, TimeUnit.SECONDS);
    }

    private synchronized Future<NodeInfo> scheduleGetCollection(String qInfo, int lifeTimeInSeconds)
    {
        final NodeEntry entry = new NodeEntry(qInfo, lifeTimeInSeconds);
        Future<NodeInfo> future = cache.get(entry);

        if (future != null)
        {
            // we want to ignore cache entries which resulted in an exception
            try
            {
                future.get(TIME_OUT, TimeUnit.MINUTES);   // we rely on the time out to stop hung entries hanging aroud.

                active.put(entry, true);                 // we mark the entry as active.
            }
            catch (Exception e)
            {
                // TODO: log
                invalidateEntry(entry);
                future = null;
            }
        }

        if (future == null)
        {
            Callable<NodeInfo> task = makeCallable(qInfo);

            future = nodeContext.getScheduledExecutor().submit(task);

            cache.put(entry, future);

            Runnable checkEntryTask = new Runnable()
            {
                @Override
                public void run()
                {
                    checkEntry(entry);
                }
            };

            scheduler.schedule(checkEntryTask, lifeTimeInSeconds, TimeUnit.SECONDS);
        }

        return future;
    }

    private void scheduleEntryCheck(final NodeEntry entry)
    {
        Runnable checkEntryTask = new Runnable()
        {
            @Override
            public void run()
            {
                checkEntry(entry);
            }
        };

        scheduler.schedule(checkEntryTask, entry.getLifeTimeInSeconds(), TimeUnit.SECONDS);
    }

    private Callable<NodeInfo> makeCallable(final String nodeName)
    {
        return new Callable<NodeInfo>()
        {
            public NodeInfo call()
                throws Exception
            {
                MessageReply reply = nodeContext.getPeerMap().get(nodeName).sendMessage(CommandMessage.Type.FETCH_NODE_INFO, new RequestCapabilities(RequestCapabilities.Type.ALL));

                if (reply.getType() == MessageReply.Type.OKAY)
                {
                    return NodeInfo.getInstance(reply.getPayload());
                }

                throw new ServiceConnectionException("Bad reply to FETCH_NODE_INFO request.");
            }
        };
    }

    public NodeInfo fetchCapabilities(String nodeName)
        throws ServiceConnectionException
    {
        return fetch(nodeName, 120);   // TODO:
    }

    public NodeInfo fetchNetworkCapabilities()
    {
        List<CapabilityMessage> capList = new ArrayList<>();

        Set<String> names = new HashSet<>(nodeContext.getPeerMap().keySet());

        for (String nodeName : names)
        {
            try
            {
                NodeInfo info = fetchCapabilities(nodeName);

                for (CapabilityMessage capabilityMessage : info.getCapabilities())
                {
                    capList.add(capabilityMessage);
                }
            }
            catch (ServiceConnectionException e)
            {
                // ignore - we'll just not include it.
            }
        }

        return new NodeInfo(nodeContext.getName(), capList.toArray(new CapabilityMessage[capList.size()]));
    }

    private NodeInfo fetch(String qInf, int lifeTimeInSeconds)
        throws ServiceConnectionException
    {
        try
        {
            return scheduleGetCollection(qInf, lifeTimeInSeconds).get(TIME_OUT, TimeUnit.MINUTES);
        }
        catch (Exception e)
        {
            throw new CapabilitiesCacheException("Exception waiting for FETCH_NODE_INFO request.", e);
        }
    }

    public void clear()
    {
        synchronized (this)
        {
            cache.clear();
            active.clear();
        }
    }

    public Service findRemoteService(Message message)
    {
        Enum type = message.getType();
        Set<String> peers = new HashSet<>(nodeContext.getPeerMap().keySet());

        for (String nodeName : peers)
        {
            try
            {
                NodeInfo info = this.fetchCapabilities(nodeName);

                for (CapabilityMessage capability : info.getCapabilities())
                {
                    if (capability.getType().equals(CapabilityMessage.Type.BOARD_HOSTING))
                    {
                        Service remoteBoard = new RemoteBoardHostingService(this.nodeContext, nodeName, capability);

                        if (remoteBoard.isAbleToHandle(message))
                        {
                            return remoteBoard;
                        }
                    }
                }
            }
            catch (ServiceConnectionException e)
            {
                // ignore
            }
        }

        return null;
    }

    private class CapabilitiesCacheException
        extends ServiceConnectionException
    {
        public CapabilitiesCacheException(String msg, Exception cause)
        {
            super(msg, cause);
        }
    }

    private class NodeEntry
    {
        private final String name;
        private final int lifeTimeInSeconds;

        NodeEntry(String name, int lifeTimeInSeconds)
        {
            this.name = name;
            this.lifeTimeInSeconds = lifeTimeInSeconds;
        }

        String getName()
        {
            return name;
        }

        int getLifeTimeInSeconds()
        {
            return lifeTimeInSeconds;
        }

        @Override
        public int hashCode()
        {
            return name.hashCode();
        }

        @Override
        public boolean equals(Object o)
        {
            // if this isn't the case we've screwed up badly!
            NodeEntry other = (NodeEntry)o;

            return this.lifeTimeInSeconds == other.lifeTimeInSeconds && this.name.equals(other.name);
        }
    }
}