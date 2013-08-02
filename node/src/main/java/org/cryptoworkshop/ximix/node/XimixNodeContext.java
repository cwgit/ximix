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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.io.Streams;
import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.config.ConfigException;
import org.cryptoworkshop.ximix.common.config.ConfigObjectFactory;
import org.cryptoworkshop.ximix.common.message.*;
import org.cryptoworkshop.ximix.common.service.*;
import org.cryptoworkshop.ximix.crypto.key.*;
import org.cryptoworkshop.ximix.crypto.operator.bc.BcECPublicKeyOperator;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.concurrent.*;

public class XimixNodeContext
    implements NodeContext
{
    private final ExecutorService connectionExecutor = Executors.newCachedThreadPool();   // TODO configurable or linked to threshold
    private final ScheduledExecutorService multiTaskExecutor = Executors.newScheduledThreadPool(5);   // TODO configurable or linked to threshold
    private final Map<Decoupler, ExecutorService> decouplers = new HashMap<>();
    private final List<Service> services = new ArrayList<>();
    private final String name;
    private final ECKeyManager ecKeyManager;
    private final BLSKeyManager blsKeyManager;
    private final RemoteServicesCache remoteServicesCache;
    private final File homeDirectory;
    private final Map<String, ServicesConnection> peerMap;
    private final CountDownLatch setupCompleteLatch = new CountDownLatch(1);
    private final Map<String, String> description;
    private final ListeningSocketInfo listeningSocketInfo;


    public XimixNodeContext(Map<String, ServicesConnection> peerMap, final Config nodeConfig)
        throws ConfigException
    {

        this.description = nodeConfig.getConfigObject("description", new DescriptionConfigFactory()).getDescription();

        this.peerMap = Collections.synchronizedMap(new HashMap<>(peerMap));

        this.decouplers.put(Decoupler.BOARD_REGISTRY, Executors.newSingleThreadExecutor());
        this.decouplers.put(Decoupler.LISTENER, Executors.newSingleThreadExecutor());
        this.decouplers.put(Decoupler.SERVICES, Executors.newSingleThreadExecutor());
        this.decouplers.put(Decoupler.SHARING, Executors.newSingleThreadExecutor());

        this.name = nodeConfig.getStringProperty("name");  // TODO:
        this.homeDirectory = nodeConfig.getHomeDirectory();

        this.peerMap.remove(this.name);

        this.ecKeyManager = new ECKeyManager(this);
        this.blsKeyManager = new BLSKeyManager(this);

        if (homeDirectory != null)
        {
            setupKeyManager(homeDirectory, ecKeyManager);
        }

        remoteServicesCache = new RemoteServicesCache(this);

        this.listeningSocketInfo = new ListeningSocketInfo(
            nodeConfig.getIntegerProperty("portNo"),
            nodeConfig.getIntegerProperty("portBacklog"),
            nodeConfig.getStringProperty("portAddress"));


        //
        // we schedule this bit to a new thread as the services require node context as an argument
        // and we want to make sure they are well formed.
        //
        this.getDecoupler(Decoupler.SERVICES).execute(new Runnable()
        {
            @Override
            public void run()
            {
                try
                {
                    List<ServiceConfig> configs = nodeConfig.getConfigObjects("services", new NodeConfigFactory());
                    for (ServiceConfig config : configs)
                    {
                        if (config.getThrowable() != null)
                        {
                            config.getThrowable().printStackTrace();   // TODO: log!
                        }
                    }
                }
                catch (ConfigException e)
                {
                    // TODO:
                }
                finally
                {
                    setupCompleteLatch.countDown();
                }
            }
        });
    }

    @Override
    public Map<Service, Map<String, Object>> getServiceStatistics()
    {
        final Map<Service, Map<String, Object>> stats = new HashMap<>();

        List<Service> serviceList = getServices();


        final CountDownLatch latch = new CountDownLatch(serviceList.size());

        ServiceStatisticsListener listener = new ServiceStatisticsListener()
        {
            @Override
            public void statisticsUpdate(Service service, Map<String, Object> details)
            {
                stats.put(service, details);
                latch.countDown();

                service.removeListener(this);
            }
        };


        for (Service s : serviceList)
        {
            s.addListener(listener);
            s.trigger(new ServiceEvent(ServiceEvent.Type.PUBLISH_STATISTICS, null));
        }

        try
        {
            latch.await(10, TimeUnit.SECONDS); // TODO Make configurable..
        }
        catch (InterruptedException e)
        {
            // Deliberately ignored.
        }

        return stats;
    }

    @Override
    public Map<String, String> getDescription()
    {
        return description;
    }

    @Override
    public ListeningSocketInfo getListeningSocketInfo()
    {
        return listeningSocketInfo;
    }

    public String getName()
    {
        return name;
    }

    public CapabilityMessage[] getCapabilities()
    {
        List<CapabilityMessage> capabilityList = new ArrayList<>();


        for (Service service : getServices())
        {
            CapabilityMessage msg = service.getCapability();
            if (msg == null)
            {                 // TODO: log error.
                System.err.println("Service " + service.getClass().getName() + " does not supply a capability.");
                continue;
            }

            capabilityList.add(msg);
        }

        return capabilityList.toArray(new CapabilityMessage[capabilityList.size()]);
    }

    private List<Service> getServices()
    {
        // we need to wait for the config task to finish
        try
        {
            setupCompleteLatch.await();
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
        }

        return services;
    }

    public void addConnection(XimixServices task)
    {
        connectionExecutor.execute(task);
    }

    public Map<String, ServicesConnection> getPeerMap()
    {
        return peerMap;
    }

    public void execute(Runnable task)
    {
        multiTaskExecutor.execute(task);
    }

    @Override
    public void schedule(Runnable task, long time, TimeUnit timeUnit)
    {
        multiTaskExecutor.schedule(task, time, timeUnit);
    }

    @Override
    public Executor getDecoupler(Decoupler task)
    {
        return decouplers.get(task);
    }

    public SubjectPublicKeyInfo getPublicKey(String keyID)
    {
        try
        {
            if (ecKeyManager.hasPrivateKey(keyID))
            {
                return ecKeyManager.fetchPublicKey(keyID);
            }
            if (blsKeyManager.hasPrivateKey(keyID))
            {
                return blsKeyManager.fetchPublicKey(keyID);
            }
        }
        catch (IOException e)
        {
            e.printStackTrace();  // TODO:

        }
        return null;
    }

    @Override
    public boolean hasPrivateKey(String keyID)
    {
        return ecKeyManager.hasPrivateKey(keyID) || blsKeyManager.hasPrivateKey(keyID);
    }

    @Override
    public PublicKeyOperator getPublicKeyOperator(String keyID)
    {
        try
        {
            SubjectPublicKeyInfo pubInfo = ecKeyManager.fetchPublicKey(keyID);
            ECPublicKeyParameters keyParameters = (ECPublicKeyParameters)PublicKeyFactory.createKey(pubInfo);

            return new BcECPublicKeyOperator(keyParameters.getParameters());
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public PrivateKeyOperator getPrivateKeyOperator(String keyID)
    {
        if (blsKeyManager.hasPrivateKey(keyID))
        {
            return blsKeyManager.getPrivateKeyOperator(keyID);
        }
        return ecKeyManager.getPrivateKeyOperator(keyID);
    }

    public Service getService(Message message)
    {
        for (Service service : getServices())
        {
            if (service.isAbleToHandle(message))
            {
                return service;
            }
        }

        if (message.getType() == CommandMessage.Type.NODE_INFO_UPDATE)
        {
            return new NodeInfoService(this);
        }

        return remoteServicesCache.findRemoteService(message);
    }

    @Override
    public boolean isStopCalled()
    {
        return multiTaskExecutor.isShutdown() || multiTaskExecutor.isTerminated();
    }

    @Override
    public ScheduledExecutorService getScheduledExecutor()
    {
        return multiTaskExecutor;
    }

    @Override
    public ThresholdKeyPairGenerator getKeyPairGenerator(Algorithm algorithm)
    {
        if (algorithm == Algorithm.BLS)
        {
            return new BLSNewDKGGenerator(algorithm, blsKeyManager);
        }

        return new ECNewDKGGenerator(algorithm, ecKeyManager);
    }

    @Override
    public String getBoardHost(String boardName)
    {
        String host = remoteServicesCache.findBoardHost(boardName);

        if (host != null)
        {
            return host;
        }

        return this.getName();
    }

    @Override
    public File getHomeDirectory()
    {
        return homeDirectory;
    }

    @Override
    public boolean shutdown(final int time, final TimeUnit timeUnit)
        throws InterruptedException
    {
        List<Runnable> tasks = connectionExecutor.shutdownNow();

        for (Runnable task : tasks)
        {
            XimixServices connection = (XimixServices)task;

            connection.stop();
        }

        // TODO need to deal with the decoupled executors.

        multiTaskExecutor.shutdown();

        return multiTaskExecutor.awaitTermination(time, timeUnit);
    }

    /**
     * Reload our previous state and register listener's if required.
     *
     * @param homeDirectory root of the node's config
     * @param keyManager    the key manager to be reloaded.
     */
    private void setupKeyManager(final File homeDirectory, KeyManager keyManager)
    {
        final File keyDir = new File(homeDirectory, "keys");
        final File store = new File(keyDir, keyManager.getID() + ".p12");

        if (store.exists())
        {
            try
            {
                // TODO: password!!!!
                keyManager.load("Hello".toCharArray(), Streams.readAll(new FileInputStream(store)));
            }
            catch (IOException e)
            {
                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            }
            catch (GeneralSecurityException e)
            {
                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            }
        }

        keyManager.addListener(new KeyManagerListener()
        {
            @Override
            public void keyAdded(KeyManager keyManager, String keyID)
            {
                if (homeDirectory != null)
                {
                    try
                    {
                        byte[] enc = keyManager.getEncoded("Hello".toCharArray());

                        if (!keyDir.exists())
                        {
                            if (!keyDir.mkdir())
                            {
                                System.err.println("Eeeek!");  // TODO
                            }
                        }

                        if (store.exists())
                        {
                            if (!store.renameTo(new File(keyDir, keyManager.getID() + ".p12.bak")))
                            {
                                System.err.println("Eeeek!"); // TODO
                            }
                        }

                        FileOutputStream fOut = new FileOutputStream(store);

                        fOut.write(enc);

                        fOut.close();
                    }
                    catch (IOException e)
                    {
                        e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                    }
                    catch (GeneralSecurityException e)
                    {
                        e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                    }
                }
            }
        });
    }

    private class NodeInfoService
        extends BasicService
    {
        public NodeInfoService(NodeContext nodeContext)
        {
            super(nodeContext);
        }

        @Override
        public CapabilityMessage getCapability()
        {
            return new CapabilityMessage(CapabilityMessage.Type.NODE_INFO, new ASN1Encodable[0]);
        }

        @Override
        public MessageReply handle(Message message)
        {
            remoteServicesCache.updateNodeInfo(NodeInfo.getInstance(message.getPayload()));

            return new MessageReply(MessageReply.Type.OKAY, new NodeInfo(XimixNodeContext.this.getName(), XimixNodeContext.this.getCapabilities()));
        }

        @Override
        public boolean isAbleToHandle(Message message)
        {
            return message.getType() == CommandMessage.Type.NODE_INFO_UPDATE;
        }
    }

    private class DescriptionConfig
    {
        private final Map<String, String> description = new HashMap<>();

        public DescriptionConfig(Node node)
        {
            NodeList nl = node.getChildNodes();
            for (int t = 0; t < nl.getLength(); t++)
            {
                Node n = nl.item(t);


                if ("detail".equals(n.getNodeName()))
                {
                    NodeList detailsList = n.getChildNodes();
                    String item = "";
                    String value = "";

                    for (int tt = 0; tt < detailsList.getLength(); tt++)
                    {
                        Node nn = detailsList.item(tt);

                        if ("item".equals(nn.getNodeName()))
                        {
                            item = nn.getTextContent();
                        }
                        else if ("value".equals(nn.getNodeName()))
                        {
                            value = nn.getTextContent();
                        }
                    }

                    description.put(item, value);

                }

            }
        }

        Map<String, String> getDescription()
        {
            return Collections.unmodifiableMap(description);
        }
    }

    private class DescriptionConfigFactory
        implements ConfigObjectFactory<DescriptionConfig>
    {
        public DescriptionConfig createObject(Node configNode)
        {
            return new DescriptionConfig(configNode);
        }
    }

    private class ServiceConfig
    {
        private Exception throwable;

        ServiceConfig(Node configNode)
        {
            NodeList xmlNodes = configNode.getChildNodes();

            for (int i = 0; i != xmlNodes.getLength(); i++)
            {
                Node xmlNode = xmlNodes.item(i);

                if (xmlNode.getNodeName().equals("service"))
                {
                    NodeList attributes = xmlNode.getChildNodes();

                    for (int j = 0; j != xmlNodes.getLength(); j++)
                    {
                        Node attrNode = attributes.item(j);

                        if (attrNode == null)
                        {
                            continue;
                        }

                        if (attrNode.getNodeName().equals("implementation"))
                        {
                            try
                            {
                                Class clazz = Class.forName(attrNode.getTextContent());

                                Constructor constructor = clazz.getConstructor(NodeContext.class, Config.class);

                                Service impl = (Service)constructor.newInstance(XimixNodeContext.this, new Config(xmlNode));

                                services.add(impl);
                            }
                            catch (ClassNotFoundException e)
                            {
                                throwable = e;
                            }
                            catch (NoSuchMethodException e)
                            {
                                throwable = e;
                            }
                            catch (InvocationTargetException e)
                            {
                                throwable = e;
                            }
                            catch (InstantiationException e)
                            {
                                throwable = e;
                            }
                            catch (IllegalAccessException e)
                            {
                                throwable = e;
                            }
                            catch (ConfigException e)
                            {
                                throwable = e;
                            }
                        }
                    }
                }
            }
        }

        public Throwable getThrowable()
        {
            return throwable;
        }
    }

    private class NodeConfigFactory
        implements ConfigObjectFactory<ServiceConfig>
    {
        public ServiceConfig createObject(Node configNode)
        {
            return new ServiceConfig(configNode);
        }
    }


}

