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
package org.cryptoworkshop.ximix.client.connection;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.bouncycastle.asn1.ASN1Encodable;
import org.cryptoworkshop.ximix.client.CommandService;
import org.cryptoworkshop.ximix.client.KeyGenerationService;
import org.cryptoworkshop.ximix.client.KeyService;
import org.cryptoworkshop.ximix.client.MonitorService;
import org.cryptoworkshop.ximix.client.NodeDetail;
import org.cryptoworkshop.ximix.client.RegistrarServiceException;
import org.cryptoworkshop.ximix.client.SigningService;
import org.cryptoworkshop.ximix.client.UploadService;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.MessageType;
import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.config.ConfigException;
import org.cryptoworkshop.ximix.common.util.DecoupledListenerHandlerFactory;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.common.util.ListenerHandler;

/**
 * Factory class to allow clients to build Ximix registrars.Once an actual registrar is built services on the running
 * network can be discovered by passing in the appropriate interface. For example:
 * <pre>
 *   XimixRegistrar registrar = XimixRegistrarFactory.createServicesRegistrar(configFile);
 *
 *   KeyService    keyFetcher = registrar.connect(KeyService.class);
 * </pre>
 */
public class XimixRegistrarFactory
{
    /**
     * Create an unprivileged registrar that can create privileged services using the configuration in configFile. An
     * unprivileged user is only allowed to upload messages and request public keys or signatures.
     *
     * @param configFile file containing the Ximix configuration to use.
     * @param eventNotifier notifier to be used in case of error messages or warnings.
     * @return a XimixRegistrar that can be used to discover services.
     * @throws ConfigException if there is an error in the configuration.
     * @throws FileNotFoundException if the File object configFile is a reference to file that does not exist.
     */
    public static XimixRegistrar createServicesRegistrar(File configFile, EventNotifier eventNotifier)
        throws ConfigException, FileNotFoundException
    {
        return createServicesRegistrar(new Config(configFile), eventNotifier);
    }

    /**
     * Create an unprivileged registrar that can create privileged services using the configuration in config. An
     * unprivileged user is only allowed to upload messages and request public keys or signatures.
     *
     * @param config Ximix configuration to use.
     * @param eventNotifier notifier to be used in case of error messages or warnings.
     * @return a XimixRegistrar that can be used to discover services.
     * @throws ConfigException if there is an error in the configuration.
     */
    public static XimixRegistrar createServicesRegistrar(Config config, final EventNotifier eventNotifier)
        throws ConfigException
    {
        final List<NodeConfig> nodes = config.getConfigObjects("node", new NodeConfigFactory());

        return new XimixRegistrar()
        {
            private final ExecutorService decoupler = Executors.newSingleThreadExecutor();

            public <T> T connect(Class<T> serviceClass)
                throws RegistrarServiceException
            {
                if (serviceClass.isAssignableFrom(UploadService.class))
                {
                    return (T)new ClientUploadService(new ServicesConnectionImpl(nodes, decoupler, eventNotifier));
                }
                if (serviceClass.isAssignableFrom(KeyService.class))
                {
                    return (T)new ClientSigningService(new AdminServicesConnectionImpl(nodes, decoupler, eventNotifier));
                }
                if (serviceClass.isAssignableFrom(SigningService.class))
                {
                    return (T)new ClientSigningService(new AdminServicesConnectionImpl(nodes, decoupler, eventNotifier));
                }

                throw new RegistrarServiceException("Unable to identify service");
            }

            @Override
            public void shutdown()
            {
                 decoupler.shutdown();
            }
        };
    }

    /**
     * Create a privileged registrar that can create privileged services using the configuration in configFile. A privileged user
     * can perform any operations on the Ximix including download, decryption and shuffling.
     *
     *
     * @param configFile file containing the Ximix configuration to use.
     * @param eventNotifier notifier to be used in case of error messages or warnings.
     * @return a XimixRegistrar that can be used to discover services.
     * @throws ConfigException if there is an error in the configuration.
     * @throws FileNotFoundException if the File object configFile is a reference to file that does not exist.
     */
    public static XimixRegistrar createAdminServiceRegistrar(File configFile, EventNotifier eventNotifier)
        throws ConfigException, FileNotFoundException
    {
        return createAdminServiceRegistrar(new Config(configFile), eventNotifier);
    }

    /**
     * Create a privileged registrar that can create privileged services using the configuration in configStream. A privileged user
     * can perform any operations on the Ximix including download, decryption and shuffling.
     *
     * @param configStream an input stream containing the Ximix configuration to use.
     * @param eventNotifier notifier to be used in case of error messages or warnings.
     * @return a XimixRegistrar that can be used to discover services.
     * @throws ConfigException if there is an error in the configuration.
     * @throws FileNotFoundException if the File object configFile is a reference to file that does not exist.
     */
    public static XimixRegistrar createAdminServiceRegistrar(InputStream configStream, EventNotifier eventNotifier)
        throws ConfigException, FileNotFoundException
    {
        return createAdminServiceRegistrar(new Config(configStream), eventNotifier);
    }

    /**
     * Create a privileged registrar that can create privileged services using the configuration in configFile. A privileged user
     * can perform any operations on the Ximix including download, decryption and shuffling.
     *
     * @param config Ximix configuration to use.
     * @param eventNotifier notifier to be used in case of error messages or warnings.
     * @return a XimixRegistrar that can be used to discover services.
     * @throws ConfigException if there is an error in the configuration.
     */
    public static XimixRegistrar createAdminServiceRegistrar(Config config, final EventNotifier eventNotifier)
        throws ConfigException, FileNotFoundException
    {
        final List<NodeConfig> nodes = config.getConfigObjects("node", new NodeConfigFactory());

        return new XimixRegistrar()
        {
            final ExecutorService decoupler = Executors.newSingleThreadExecutor();

            public <T> T connect(Class<T> serviceClass)
                throws RegistrarServiceException
            {
                AdminServicesConnectionImpl adminServicesConnection = new AdminServicesConnectionImpl(nodes, decoupler, eventNotifier);

                try
                {
                    adminServicesConnection.activate();
                }
                catch (ServiceConnectionException e)
                {
                    eventNotifier.notify(EventNotifier.Level.ERROR, "Unable to activate connection");

                    throw new RegistrarServiceException("Unable to activate registrar");
                }

                if (serviceClass.isAssignableFrom(CommandService.class))
                {
                    return (T)new ClientCommandService(adminServicesConnection);
                }
                if (serviceClass.isAssignableFrom(KeyGenerationService.class))
                {
                    return (T)new KeyGenerationCommandService(adminServicesConnection);
                }
                if (serviceClass.isAssignableFrom(UploadService.class))
                {
                    return (T)new ClientUploadService(adminServicesConnection);
                }
                if (serviceClass.isAssignableFrom(SigningService.class))
                {
                    return (T)new ClientSigningService(adminServicesConnection);
                }
                if (serviceClass.isAssignableFrom(MonitorService.class))
                {
                    return (T)new ClientNodeHealthMonitor(adminServicesConnection, getDetailMap(nodes, eventNotifier));
                }

                throw new RegistrarServiceException("Unable to identify service");
            }

            @Override
            public void shutdown()
            {
                decoupler.shutdown();
            }
        };
    }

    private static class AdminServicesConnectionImpl
        implements AdminServicesConnection
    {
        private final EventNotifier eventNotifier;
        private final NodeConnectionListener nodeConnectionListener;

        private Map<String, Boolean> connectionStatus = Collections.synchronizedMap(new HashMap<String, Boolean>());
        private Map<String, NodeServicesConnection> connectionMap = Collections.synchronizedMap(new HashMap<String, NodeServicesConnection>());
        private Set<CapabilityMessage> capabilitySet = Collections.synchronizedSet(new HashSet<CapabilityMessage>());

        public AdminServicesConnectionImpl(List<NodeConfig> configList, Executor decoupler, EventNotifier eventNotifier)
        {
            ListenerHandler<EventNotifier> notifierHandler = new DecoupledListenerHandlerFactory(decoupler, eventNotifier).createHandler(EventNotifier.class);
            notifierHandler.addListener(eventNotifier);
            this.eventNotifier = notifierHandler.getNotifier();

            ListenerHandler<NodeConnectionListener> listenerHandler = new DecoupledListenerHandlerFactory(decoupler, eventNotifier).createHandler(NodeConnectionListener.class);
            listenerHandler.addListener(new NodeConnectionListener()
            {
                @Override
                public void status(String name, boolean isAvailable)
                {
                    connectionStatus.put(name, isAvailable);

                    if (isAvailable)
                    {
                        try
                        {
                            capabilitySet.addAll(Arrays.asList(connectionMap.get(name).getCapabilities()));
                        }
                        catch (ServiceConnectionException e)
                        {
                            e.printStackTrace();      // TODO: should never happen... but...
                        }
                    }
                }
            });
            this.nodeConnectionListener = listenerHandler.getNotifier();

            for (int i = 0; i != configList.size(); i++)
            {
                final NodeConfig nodeConf = configList.get(i);

                if (nodeConf.getThrowable() == null)
                {
                    final NodeServicesConnection connection = new NodeServicesConnection(nodeConf, nodeConnectionListener, eventNotifier);

                    connectionMap.put(connection.getName(), connection);
                }
                else
                {
                    eventNotifier.notify(EventNotifier.Level.ERROR, "Exception processing connection config: " + nodeConf.getThrowable().getMessage(), nodeConf.getThrowable());
                }
            }
        }

        @Override
        public void shutdown()
            throws ServiceConnectionException
        {
            for (NodeServicesConnection connection : connectionMap.values())
            {
                try
                {
                    connection.shutdown();
                }
                catch (ServiceConnectionException e)
                {
                    eventNotifier.notify(EventNotifier.Level.WARN, "Exception on shutting down connection to " + connection.getName() + ": " +e.getMessage(), e);
                }
            }
        }

        @Override
        public void activate()
            throws ServiceConnectionException
        {
            // TODO: this could be done in parallel
            for (NodeServicesConnection connection : connectionMap.values())
            {
                try
                {
                    connection.activate();
                }
                catch (Exception e)
                {
                    eventNotifier.notify(EventNotifier.Level.WARN, "Node " + connection.getName() + " not yet available.");
                }
            }
        }

        public CapabilityMessage[] getCapabilities()
        {
            return capabilitySet.toArray(new CapabilityMessage[capabilitySet.size()]);
        }

        @Override
        public EventNotifier getEventNotifier()
        {
            return eventNotifier;
        }

        public MessageReply sendMessage(MessageType type, ASN1Encodable messagePayload)
            throws ServiceConnectionException
        {
            if (getActiveNodeNames().isEmpty())
            {
                throw new ServiceConnectionException("No Ximix nodes are available!");
            }

            try
            {
                return connectionMap.get(getActiveNodeNames().iterator().next()).sendMessage(type, messagePayload);
            }
            catch (ServiceConnectionException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new ServiceConnectionException("Unable to send message: " + e.getMessage(), e);
            }
        }

        @Override
        public Set<String> getActiveNodeNames()
        {
            Set<String>  nodeNames = new HashSet<>();

            for (String name : connectionStatus.keySet())
            {
                if (connectionStatus.get(name))     // true is active
                {
                     nodeNames.add(name);
                }
            }

            return nodeNames;
        }

        public MessageReply sendMessage(String nodeName, MessageType type, ASN1Encodable messagePayload)
            throws ServiceConnectionException
        {

            NodeServicesConnection connection = connectionMap.get(nodeName);
            if (connection == null)
            {
                throw new ServiceConnectionException("Connection '" + nodeName + "' was not found.");
            }

            return connection.sendMessage(type, messagePayload);
        }
    }

    private static Map<String, NodeDetail> getDetailMap(List<NodeConfig> nodes, EventNotifier eventNotifier)
    {
        Map<String, NodeDetail> details = new HashMap<>(nodes.size());

        for (NodeConfig config : nodes)
        {
            if (config.getThrowable() == null)
            {
                details.put(config.getName(), new NodeDetail(config.getName(), config.getAddress(), config.getPortNo()));
            }
            else
            {
                eventNotifier.notify(EventNotifier.Level.ERROR, "Exception getting detail map: " + config.getThrowable().getMessage(), config.getThrowable());
            }
        }

        return details;
    }
}
