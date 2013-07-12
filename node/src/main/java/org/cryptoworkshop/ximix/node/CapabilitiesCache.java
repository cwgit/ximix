package org.cryptoworkshop.ximix.node;

import org.cryptoworkshop.ximix.common.message.*;
import org.cryptoworkshop.ximix.common.service.NodeContext;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.*;

/**
 * Maintains a cache of node capabilities within the mixnet
 */
public class CapabilitiesCache
{

    long expireAfterPeriod = 2 * 60 * 1000; // TODO make configurable.
    private HashMap<CapabilityCacheKey, List<CapabilityCacheEntry>> map = new HashMap<>();
    private NodeContext nodeContext = null;

    public CapabilitiesCache(NodeContext nodeContext)
    {
        this.nodeContext = nodeContext;

    }



    /**
     * Puts a copy of the capability.
     *
     * @param key   The key.
     * @param entry The entry.
     */
    public void putCapability(CapabilityCacheKey key, CapabilityCacheEntry entry)
    {
        synchronized (CapabilitiesCache.this)
        {
            putCapabilityNoSynchronization(key, entry);
        }
    }

    private void expireEntriesNoSynchronization(CapabilityCacheKey key)
    {
        List<CapabilityCacheEntry> l = map.get(key);
        if (l == null || l.isEmpty())
        {
            return;
        }

        long time = System.currentTimeMillis();
        for (int t = l.size() - 1; t >= 0; t--)
        {
            if (l.get(t).hasExpired(time))
            {
                l.remove(t);
            }
        }
    }

    /**
     * An unsynchronized addition of a capability.
     *
     * @param key   The key.
     * @param entry The entry.
     */
    private void putCapabilityNoSynchronization(CapabilityCacheKey key, CapabilityCacheEntry entry)
    {
        if (!map.containsKey(key))
        {
            map.put(key, new ArrayList<CapabilityCacheEntry>());
        }

        //
        // Remove existing entry.
        //
        List<CapabilityCacheEntry> l = map.get(key);
        for (int t = l.size() - 1; t >= 0; t--)
        {
            if (l.get(t).equals(entry))
            {
                l.remove(t);
            }
        }

        // Add new entry.
        l.add(entry);
    }

    /**
     * This method will move a provider from the head of the
     * providers list to the back for  given key.
     *
     * @param key The key.
     */
    public void cycleProviders(CapabilityCacheKey key)
    {
        synchronized (CapabilitiesCache.this)
        {
            List<CapabilityCacheEntry> l = map.get(key);
            if (l == null || l.isEmpty())
            {
                return; // May have been cleaned up in mean time.
            }

            CapabilityCacheEntry ent = l.remove(0);
            l.add(ent);
        }
    }

    public void putFromNodeInfo(NodeInfo info)
    {
        if (info.getCapabilities() == null)
        {
            return; //TODO Log this.
        }

        for (CapabilityMessage msg : info.getCapabilities())
        {
            putFromCapabilityMessage(msg, true, info.getName(), expireAfter());
        }
    }

    private long expireAfter()
    {
        return System.currentTimeMillis() + expireAfterPeriod;
    }

    /**
     * Get the capability.
     *
     * @param key The key.
     * @return A future to the result.
     */
    public synchronized CapabilityResult getCapability(final CapabilityCacheKey key)
    {
        final CapabilityResult result = new CapabilityResult();

        //
        // TODO All capabilities searches result in scheduled job. Consider doing check in this thread first before invoking..
        //

        nodeContext.execute(makeLookupRunnable(result, key));

        return result;
    }

    private Runnable makeLookupRunnable(final CapabilityResult party, final CapabilityCacheKey key)
    {
        return new Runnable()
        {
            @Override
            public void run()
            {

                //
                // Expire entries for this key.
                //
                synchronized (CapabilitiesCache.this)
                {
                    expireEntriesNoSynchronization(key);
                }


                List<CapabilityCacheEntry> results = null;

                //
                // Query cache.
                //
                synchronized (CapabilitiesCache.this)
                {
                    results = map.get(key);
                }


                if (results == null || results.isEmpty())
                {

                    //
                    // Nothing found in original search so we query every node looking for the capability.
                    //
                    Iterator<String> keys = nodeContext.getPeerMap().keySet().iterator();

                    while (keys.hasNext())
                    {
                        try
                        {
                            requestCapabilitiesFromNode(keys.next(), true);
                        }
                        catch (Exception ex)
                        {
                            ex.printStackTrace(); // TODO
                        }

                    }

                    //
                    // We have polled the network for the capability.
                    // Check again.
                    //

                    synchronized (CapabilitiesCache.this)
                    {
                        results = map.get(key);
                    }

                    if (results == null || results.isEmpty())
                    {
                        // Nothing was found so signal party and exit.
                        party.notFound();
                        return;
                    }
                }

                // TODO enable Round Robin. cycleProviders(key);
                party.complete(results.get(0));

            }
        };
    }

    /**
     * Request new capability entries from remote node.
     *
     * @param node The node id.
     * @return A list of keys retrieved from that node.
     * @throws Exception throws all exceptions.
     */
    private void requestCapabilitiesFromNode(String node, boolean synchronize)
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

        for (CapabilityMessage msg : remote.getCapabilities())
        {
            putFromCapabilityMessage(msg, synchronize, node, expireAfter());

        }

    }

    /**
     * Put from a capabilities message.
     *
     * @param msg         The message.
     * @param synchronize true - will update the map synchronized on this.
     * @param node        The name of the node.
     * @param expireAfter the timestamp to expire the entry after.
     */
    private void putFromCapabilityMessage(CapabilityMessage msg, boolean synchronize, String node, long expireAfter)
    {
        SimpleCapabilityCacheKey key = null;
        CapabilityCacheEntry val = null;

        switch (msg.getType())
        {
            case BOARD_HOSTING:
                key = SimpleCapabilityCacheKey.BOARD_HOSTING;
                val = new NodeCapabilityCacheEntry(node, expireAfter);
                break;

            case DECRYPTION:
                key = SimpleCapabilityCacheKey.DECRYPTION;
                val = new NodeCapabilityCacheEntry(node, expireAfter);
                break;

            case ENCRYPTION:
                key = SimpleCapabilityCacheKey.ENCRYPTION;
                val = new NodeCapabilityCacheEntry(node, expireAfter);
                break;

            case KEY_RETRIEVAL:
                key = SimpleCapabilityCacheKey.KEY_RETRIEVAL;
                val = new NodeCapabilityCacheEntry(node, expireAfter);
                break;

            case KEY_GENERATION:
                key = SimpleCapabilityCacheKey.KEY_GENERATION;
                val = new NodeCapabilityCacheEntry(node, expireAfter);
                break;

            case SIGNING:
                key = SimpleCapabilityCacheKey.SIGNING;
                val = new NodeCapabilityCacheEntry(node, expireAfter);
                break;
        }

        if (synchronize)
        {
            putCapability(key, val);
        }
        else
        {
            putCapabilityNoSynchronization(key, val);
        }

    }


    public static interface CapabilityCacheEntry
    {
        boolean hasExpired(long timestamp);

        CapabilityCacheEntry copy();

        boolean equals(Object o);

        int hashCode();

    }


    public static interface CapabilityCacheKey
    {
        boolean equals(Object o);

        int hashCode();
    }

    public static class NodeCapabilityCacheEntry
        implements CapabilityCacheEntry
    {
        protected long notAfter = Long.MIN_VALUE;
        protected String name = null;
        protected CapabilityCacheKey key = null;

        public NodeCapabilityCacheEntry(String name, long notAfter)
        {
            this.notAfter = notAfter;
            this.name = name;
        }

        protected NodeCapabilityCacheEntry withKey(CapabilityCacheKey key)
        {
            this.key = key;
            return this;
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

    public static class SimpleCapabilityCacheKey
        implements CapabilityCacheKey
    {

        public static final SimpleCapabilityCacheKey BOARD_HOSTING = new SimpleCapabilityCacheKey(SimpleType.BOARD_HOSTING);
        public static final SimpleCapabilityCacheKey DECRYPTION = new SimpleCapabilityCacheKey(SimpleType.DECRYPTION);
        public static final SimpleCapabilityCacheKey ENCRYPTION = new SimpleCapabilityCacheKey(SimpleType.ENCRYPTION);
        public static final SimpleCapabilityCacheKey KEY_RETRIEVAL = new SimpleCapabilityCacheKey(SimpleType.KEY_RETRIEVAL);
        public static final SimpleCapabilityCacheKey KEY_GENERATION = new SimpleCapabilityCacheKey(SimpleType.KEY_GENERATION);
        public static final SimpleCapabilityCacheKey SIGNING = new SimpleCapabilityCacheKey(SimpleType.SIGNING);
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

        private static enum SimpleType
        {
            BOARD_HOSTING,
            DECRYPTION,
            ENCRYPTION,
            KEY_RETRIEVAL,
            KEY_GENERATION,
            SIGNING
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
