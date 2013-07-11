package org.cryptoworkshop.ximix.node;

import org.cryptoworkshop.ximix.common.message.*;
import org.cryptoworkshop.ximix.common.service.NodeContext;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.Lock;

/**
 * Maintains a cache of node capabilities within the mixnet
 */
public class CapabilitiesCache
{
    private HashMap<CapabilityCacheKey, CapabilityCacheEntry> map = new HashMap<>();
    private HashMap<CapabilityCacheKey, List<CapabilityResult>> interestedParties = new HashMap<>();


    private NodeContext nodeContext = null;

    public CapabilitiesCache(NodeContext nodeContext)
    {
        this.nodeContext = nodeContext;
    }

    private synchronized CapabilityResult getCapability(final CapabilityCacheKey key)
    {
        final CapabilityResult result = new CapabilityResult();


        //
        //  Sync on cache for the initial lookup.
        //
        synchronized (CapabilitiesCache.this)
        {
            final CapabilityCacheEntry entry = map.get(key);


            //
            // Check for not found or not expired.
            //
            if (entry == null || entry.hasExpired(System.currentTimeMillis()))
            {
                //
                // No value or expired then we need to look at forking and doing a lookup.
                //
                // 1. Check that we are not already waiting for a result.

                List<CapabilityResult> parties = interestedParties.get(key);

                //
                // If parties is null then we are not already doing a lookup.
                // In this case we can set up for and then schedule a lookup.
                //
                if (parties == null)
                {
                    parties = new ArrayList<>();
                    parties.add(result);

                    //
                    // Schedule the lookup this runs in another thread.
                    //
                    nodeContext.execute(makeLookupRunnable(parties, key, entry));
                }
                else
                {
                    //
                    // There is a lookup pending add this result to this list that will get notified of a result.
                    // when the lookup completes.
                    //
                    parties.add(result);
                }

            }
            else
            {
                //
                // The entry was found in the cache and was valid so we return a copy of the cached value.
                //
                result.complete(entry.copy());
            }
        }


        return result;
    }

    private Runnable makeLookupRunnable(final List<CapabilityResult> _parties, final CapabilityCacheKey key, final CapabilityCacheEntry entry)
    {
        return new Runnable()
        {
            @Override
            public void run()
            {
                if (entry == null)
                {
                    //
                    // Nothing found in original search so we query every node looking for the capability.
                    //
                    Iterator<String> keys = nodeContext.getPeerMap().keySet().iterator();
                    while (keys.hasNext())
                    {
                        requestUpdateNew(((NodeCapabilityCacheEntry)entry).getName(), _parties);
                    }
                }
                else
                {
                    //
                    // We had an expired value so we need to do a refresh.
                    //
                    requestUpdateNew(((NodeCapabilityCacheEntry)entry).getName(), _parties);
                }


                //
                // At this point we have a done the lookup so we can retest the cache.
                //

                synchronized (CapabilitiesCache.this)
                {
                    CapabilityCacheEntry entry = map.get(key);

                    //
                    // Still not found.
                    //
                    if (entry == null)
                    {
                        for (CapabilityResult r : _parties)
                        {
                            r.notFound();
                        }

                    }
                    //
                    // Still expired.
                    //
                    else if (entry.hasExpired(System.currentTimeMillis()))
                    {
                        for (CapabilityResult r : _parties)
                        {
                            r.couldNotUpdate();
                        }
                    }


                    interestedParties.remove(key);

                }


            }
        };
    }


    /**
     * Request info from a node and update it with new.
     *
     * @param name     The entry.
     * @param _parties The list of interested parties.
     */
    private void requestUpdateNew(String name, List<CapabilityResult> _parties)
    {
        Map<CapabilityCacheKey, CapabilityCacheEntry> val = null;
        try
        {
            val = requestCapabilities(name);
            synchronized (CapabilitiesCache.this)
            {
                map.putAll(val);
            }
        }
        catch (Exception e)
        {
            synchronized (CapabilitiesCache.this)
            {
                for (CapabilityResult r : _parties)
                {
                    r.failed(e);
                }
            }

        }


    }


    /**
     * Request new capability entries from remote node.
     *
     * @param node The node id.
     * @return A map of new entries.
     * @throws Exception throws all exceptions.
     */
    private Map<CapabilityCacheKey, CapabilityCacheEntry> requestCapabilities(String node)
        throws Exception
    {

        MessageReply msgR = nodeContext.getPeerMap().get(node).sendMessage(
            CommandMessage.Type.FETCH_NODE_INFO,
            new RequestCapabilities(RequestCapabilities.Type.ALL));
        NodeInfo remote = (NodeInfo)msgR.getPayload();


        if (remote.getCapabilities() == null)
        {
            throw new RuntimeException("Node " + node + " has no capabilities.");
        }

        Map<CapabilityCacheKey, CapabilityCacheEntry> out = new HashMap<>();


        long expireAfter = 2 * 60 * 1000; // TODO make configurable.


        for (CapabilityMessage msg : remote.getCapabilities())
        {
            switch (msg.getType())
            {
                case BOARD_HOSTING:

                    break;

                case DECRYPTION:
                    break;

                case ENCRYPTION:
                    break;

                case KEY_RETRIEVAL:
                    break;

                case KEY_GENERATION:
                    break;

                case SIGNING:
                    break;
            }
        }


        return out;
    }


    public static interface CapabilityCacheEntry
    {
        boolean hasExpired(long timestamp);

        CapabilityCacheEntry copy();
    }


    public static class NodeCapabilityCacheEntry
        implements CapabilityCacheEntry
    {
        protected long notAfter = Long.MIN_VALUE;
        protected String name = null;


        public NodeCapabilityCacheEntry(String name, long notAfter)
        {
            this.notAfter = notAfter;
            this.name = name;
        }

        @Override
        public boolean hasExpired(long timestamp)
        {
            return notAfter < timestamp;
        }

        @Override
        public CapabilityCacheEntry copy()
        {
            return new NodeCapabilityCacheEntry(name, notAfter);
        }

        public long getNotAfter()
        {
            return notAfter;
        }

        public String getName()
        {
            return name;
        }
    }


    public static interface CapabilityCacheKey
    {

    }

    public static class SimpleCapabilityCacheKey
        implements CapabilityCacheKey
    {

        public static final SimpleCapabilityCacheKey BOARD_HOSTING = new SimpleCapabilityCacheKey(SimpleType.BOARD_HOSTING);
        public static final SimpleCapabilityCacheKey DECRYPTION = new SimpleCapabilityCacheKey(SimpleType.DECRYPTION);
        public static final SimpleCapabilityCacheKey ENCRYPTION = new SimpleCapabilityCacheKey(SimpleType.ENCRYPTION);
        public static final SimpleCapabilityCacheKey KEY_RETRIEVAL = new SimpleCapabilityCacheKey(SimpleType.KEY_RETRIEVAL);
        public static final SimpleCapabilityCacheKey KEY_GENERATION = new SimpleCapabilityCacheKey(SimpleType.KEY_GENERATION);
        public static final SimpleCapabilityCacheKey SIGNING = new SimpleCapabilityCacheKey(SimpleType.SIGNING);


        private static enum SimpleType
        {
            BOARD_HOSTING,
            DECRYPTION,
            ENCRYPTION,
            KEY_RETRIEVAL,
            KEY_GENERATION,
            SIGNING
        }

        private SimpleType type = null;

        private SimpleCapabilityCacheKey(SimpleType type)
        {
            this.type = type;
        }

        @Override
        public boolean equals(Object o)
        {
            if (this == o)
            {
                return true;
            }
            if (o == null || getClass() != o.getClass())
            {
                return false;
            }

            SimpleCapabilityCacheKey that = (SimpleCapabilityCacheKey)o;

            if (type != that.type)
            {
                return false;
            }

            return true;
        }

        @Override
        public int hashCode()
        {
            return type.hashCode();
        }
    }

    public static class CapabilityResult
        implements Future<CapabilityCacheEntry>
    {
        private CountDownLatch latch = new CountDownLatch(1);
        private CapabilityCacheEntry result = null;
        private boolean notFound = false;
        private boolean couldNotUpdate = false;
        private Throwable executionException = null;

        @Override
        public boolean cancel(boolean mayInterruptIfRunning)
        {
            throw new RuntimeException("Cancel is not supported.");
        }

        protected void complete(CapabilityCacheEntry entry)
        {
            this.result = entry;
            latch.countDown();
        }

        protected void notFound()
        {
            this.notFound = true;
            latch.countDown();
        }

        protected void failed(Throwable executionException)
        {
            this.executionException = executionException;
            latch.countDown();
        }

        protected void couldNotUpdate()
        {
            couldNotUpdate = true;
            latch.countDown();
        }


        @Override
        public boolean isCancelled()
        {
            return false;
        }

        @Override
        public boolean isDone()
        {
            return latch.getCount() == 0;
        }

        public boolean isCouldNotUpdate()
        {
            return couldNotUpdate;
        }

        @Override
        public CapabilityCacheEntry get()
            throws InterruptedException, ExecutionException
        {
            latch.await();
            if (executionException != null)
            {
                throw new ExecutionException(executionException);
            }
            return result;
        }

        @Override
        public CapabilityCacheEntry get(long timeout, TimeUnit unit)
            throws InterruptedException, ExecutionException, TimeoutException
        {
            if (!latch.await(timeout, unit))
            {
                throw new TimeoutException("Cache did return in: " + timeout + " " + unit);
            }

            if (executionException != null)
            {
                throw new ExecutionException(executionException);
            }

            return result;
        }

        public boolean isNotFound()
        {
            return notFound;
        }

        public Throwable getExecutionException()
        {
            return executionException;
        }
    }

}
