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
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
import org.cryptoworkshop.ximix.common.util.EventNotifier;

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
     * @return a XimixRegistrar that can be used to discover services.
     * @throws ConfigException if there is an error in the configuration.
     * @throws FileNotFoundException if the File object configFile is a reference to file that does not exist.
     */
    public static XimixRegistrar createServicesRegistrar(File configFile)
        throws ConfigException, FileNotFoundException
    {
        return createServicesRegistrar(new Config(configFile));
    }

    /**
     * Create an unprivileged registrar that can create privileged services using the configuration in config. An
     * unprivileged user is only allowed to upload messages and request public keys or signatures.
     *
     * @param config Ximix configuration to use.
     * @return a XimixRegistrar that can be used to discover services.
     * @throws ConfigException if there is an error in the configuration.
     */
    public static XimixRegistrar createServicesRegistrar(Config config)
        throws ConfigException
    {
        final List<NodeConfig> nodes = config.getConfigObjects("node", new NodeConfigFactory());

        return new XimixRegistrar()
        {
            public <T> T connect(Class<T> serviceClass)
                throws RegistrarServiceException
            {
                if (serviceClass.isAssignableFrom(UploadService.class))
                {
                    return (T)new ClientUploadService(new ServicesConnectionImpl(nodes));
                }
                if (serviceClass.isAssignableFrom(KeyService.class))
                {
                    return (T)new ClientSigningService(new AdminServicesConnectionImpl(nodes));
                }
                if (serviceClass.isAssignableFrom(SigningService.class))
                {
                    return (T)new ClientSigningService(new AdminServicesConnectionImpl(nodes));
                }

                throw new RegistrarServiceException("Unable to identify service");
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
            public <T> T connect(Class<T> serviceClass)
                throws RegistrarServiceException
            {
                if (serviceClass.isAssignableFrom(CommandService.class))
                {
                    return (T)new ClientCommandService(new AdminServicesConnectionImpl(nodes), eventNotifier);
                }
                if (serviceClass.isAssignableFrom(KeyGenerationService.class))
                {
                    return (T)new KeyGenerationCommandService(new AdminServicesConnectionImpl(nodes));
                }
                if (serviceClass.isAssignableFrom(UploadService.class))
                {
                    return (T)new ClientUploadService(new AdminServicesConnectionImpl(nodes));
                }
                if (serviceClass.isAssignableFrom(SigningService.class))
                {
                    return (T)new ClientSigningService(new AdminServicesConnectionImpl(nodes));
                }
                if (serviceClass.isAssignableFrom(MonitorService.class))
                {
                    return (T)new ClientNodeHealthMonitor(new AdminServicesConnectionImpl(nodes), getDetailMap(nodes));
                }

                throw new RegistrarServiceException("Unable to identify service");
            }
        };
    }

    private static class AdminServicesConnectionImpl
        implements AdminServicesConnection
    {
        private Map<String, NodeServicesConnection> connectionMap = Collections.synchronizedMap(new HashMap<String, NodeServicesConnection>());
        private Set<CapabilityMessage> capabilitySet = new HashSet<>();

        public AdminServicesConnectionImpl(List<NodeConfig> configList)
        {
            for (int i = 0; i != configList.size(); i++)
            {
                final NodeConfig nodeConf = configList.get(i);

                if (nodeConf.getThrowable() == null)
                {
                    // TODO: we should query each node to see what it's capabilities are.
                    try
                    {
                        NodeServicesConnection connection = new NodeServicesConnection(nodeConf);

                        capabilitySet.addAll(Arrays.asList(connection.getCapabilities()));

                        connectionMap.put(connection.getName(), connection);
                    }
                    catch (IOException e)
                    {
                        continue;
                    }
                }
                else
                {
                    nodeConf.getThrowable().printStackTrace();
                }
            }
        }

        @Override
        public void close()
            throws ServiceConnectionException
        {
            Iterator<NodeServicesConnection> e = connectionMap.values().iterator();
            while (e.hasNext())
            {
                e.next().close();
            }
        }

        public CapabilityMessage[] getCapabilities()
        {
            return capabilitySet.toArray(new CapabilityMessage[capabilitySet.size()]);
        }

        public MessageReply sendMessage(MessageType type, ASN1Encodable messagePayload)
            throws ServiceConnectionException
        {
            return connectionMap.get(getActiveNodeNames().iterator().next()).sendMessage(type, messagePayload);
        }

        @Override
        public Set<String> getActiveNodeNames()
        {
            // TODO: this should only return names with an active connection
            return new HashSet<>(connectionMap.keySet());
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

    private static Map<String, NodeDetail> getDetailMap(List<NodeConfig> nodes)
    {
        Map<String, NodeDetail> details = new HashMap<>(nodes.size());

        for (NodeConfig config : nodes)
        {
            if (config.getThrowable() == null)
            {
                details.put(config.getName(), new NodeDetail(config.getName(), config.getAddress(), config.getPortNo()));
            }
        }

        return details;
    }
}
