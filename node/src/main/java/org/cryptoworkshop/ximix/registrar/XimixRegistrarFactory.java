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
package org.cryptoworkshop.ximix.registrar;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.conf.ConfigException;
import org.cryptoworkshop.ximix.common.conf.ConfigObjectFactory;
import org.cryptoworkshop.ximix.common.message.Capability;
import org.cryptoworkshop.ximix.common.message.ClientMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.MessageType;
import org.cryptoworkshop.ximix.common.message.NodeInfo;
import org.cryptoworkshop.ximix.common.service.AdminServicesConnection;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.common.service.SpecificServicesConnection;
import org.cryptoworkshop.ximix.crypto.client.KeyGenerationService;
import org.cryptoworkshop.ximix.crypto.client.KeyService;
import org.cryptoworkshop.ximix.crypto.client.SigningService;
import org.cryptoworkshop.ximix.crypto.client.ClientSigningService;
import org.cryptoworkshop.ximix.crypto.service.NodeKeyGenerationService;
import org.cryptoworkshop.ximix.mixnet.admin.ClientCommandService;
import org.cryptoworkshop.ximix.mixnet.admin.CommandService;
import org.cryptoworkshop.ximix.mixnet.admin.KeyGenerationCommandService;
import org.cryptoworkshop.ximix.mixnet.client.ClientUploadService;
import org.cryptoworkshop.ximix.mixnet.client.UploadService;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class XimixRegistrarFactory
{
    public static XimixRegistrar createServicesRegistrar(File config)
        throws ConfigException
    {
        final List<NodeConfig> nodes = new Config(config).getConfigObjects("node", new NodeConfigFactory());

        return new XimixRegistrar()
        {
            public <T> T connect(Class<T> serviceClass)
                throws RegistrarServiceException
            {
                if (serviceClass.isAssignableFrom(UploadService.class))
                {
                    return (T)new ClientUploadService(new ServicesConnectionImpl(nodes));
                }
                else if (serviceClass.isAssignableFrom(KeyService.class))
                {
                    return (T)new ClientSigningService(new ServicesConnectionImpl(nodes));
                }
                else if (serviceClass.isAssignableFrom(SigningService.class))
                {
                    return (T)new ClientSigningService(new ServicesConnectionImpl(nodes));
                }

                throw new RegistrarServiceException("Unable to identify service");
            }
        };
    }

    public static XimixRegistrar createAdminServiceRegistrar(File config)
        throws ConfigException
    {
        final List<NodeConfig> nodes = new Config(config).getConfigObjects("node", new NodeConfigFactory());

        return new XimixRegistrar()
        {
            public <T> T connect(Class<T> serviceClass)
                throws RegistrarServiceException
            {
                if (serviceClass.isAssignableFrom(CommandService.class))
                {
                    return (T)new ClientCommandService(new AdminServicesConnectionImpl(nodes));
                }
                if (serviceClass.isAssignableFrom(KeyGenerationService.class))
                {
                    return (T)new KeyGenerationCommandService(new AdminServicesConnectionImpl(nodes));
                }
                if (serviceClass.isAssignableFrom(UploadService.class))
                {
                    return (T)new ClientUploadService(new AdminServicesConnectionImpl(nodes));
                }

                throw new RegistrarServiceException("Unable to identify service");
            }
        };
    }


    public static Map<String, ServicesConnection> createServicesRegistrarMap(InputStream config)
            throws ConfigException
    {
        final List<NodeConfig> nodes = new Config(config).getConfigObjects("node", new NodeConfigFactory());

        return createServicesRegistrarMap(nodes);
    }

    public static Map<String, ServicesConnection> createServicesRegistrarMap(File config)
        throws ConfigException, FileNotFoundException
    {
        return createServicesRegistrarMap(new FileInputStream(config));
    }

    private static Map<String, ServicesConnection> createServicesRegistrarMap(List<NodeConfig> nodes)
    {
        Map <String, ServicesConnection> rMap = new HashMap<String, ServicesConnection>();

        for (int i = 0; i != nodes.size(); i++)
        {
            NodeConfig node = nodes.get(i);

            final String name = node.getName();
            final List<NodeConfig> thisNode = Collections.singletonList(node);

            rMap.put(name, new ServicesConnectionImpl(thisNode));
        }

        return rMap;
    }

    private static class NodeConfig
    {
        private InetAddress address;
        private int portNo;
        private String name;
        private Exception throwable;

        NodeConfig(Node configNode)
        {
            NodeList xmlNodes = configNode.getChildNodes();

            for (int i = 0; i != xmlNodes.getLength(); i++)
            {
                Node xmlNode = xmlNodes.item(i);

                if (xmlNode.getNodeName().equals("host"))
                {
                    try
                    {
                        address = InetAddress.getByName(xmlNode.getTextContent());
                    }
                    catch (UnknownHostException e)
                    {
                        throwable = e;
                    }
                }
                else if (xmlNode.getNodeName().equals("portNo"))
                {
                    portNo = Integer.parseInt(xmlNode.getTextContent());
                }
                else if (xmlNode.getNodeName().equals("name"))
                {
                    name = xmlNode.getTextContent().trim();
                }
            }
        }

        public Throwable getThrowable()
        {
            return throwable;
        }

        public InetAddress getAddress()
        {
            return address;
        }

        public int getPortNo()
        {
            return portNo;
        }

        public String getName()
        {
            return name;
        }
    }

    private static class NodeConfigFactory
        implements ConfigObjectFactory<NodeConfig>
    {
        public NodeConfig createObject(Node configNode)
        {
            return new NodeConfig(configNode);
        }
    }

    private static class NodeServicesConnection
        implements SpecificServicesConnection
    {
        private NodeInfo nodeInfo;
        private Socket connection;
        private InputStream cIn;
        private OutputStream cOut;

        public NodeServicesConnection(NodeConfig config)
            throws IOException
        {
            this.connection = new Socket(config.getAddress(), config.getPortNo());

            if (connection != null)
            {
                cOut = connection.getOutputStream();
                cIn = connection.getInputStream();
            }

            ASN1InputStream aIn = new ASN1InputStream(cIn, 30000); // TODO:

            nodeInfo = NodeInfo.getInstance(aIn.readObject());
        }

        public String getName()
        {
            return nodeInfo.getName();
        }

        public Capability[] getCapabilities()
        {
            return nodeInfo.getCapabilities();
        }

        public MessageReply sendMessage(MessageType type, ASN1Encodable messagePayload)
            throws ServiceConnectionException
        {
            try
            {
                synchronized (this)
                {
                    if (type instanceof ClientMessage.Type)
                    {
                        cOut.write(new ClientMessage((ClientMessage.Type)type, messagePayload).getEncoded());
                    }
                    else
                    {
                        cOut.write(new CommandMessage((CommandMessage.Type)type, messagePayload).getEncoded());
                    }
                    return MessageReply.getInstance(new ASN1InputStream(cIn, 100000).readObject());      // TODO
                }
            }
            catch (Exception e)
            {                                     e.printStackTrace();
                // TODO: this should only happen when we've run out of nodes.
                throw new ServiceConnectionException("couldn't send");
            }
        }
    }

    private static class ServicesConnectionImpl
        implements ServicesConnection
    {
        private NodeServicesConnection connection;
        private NodeConfig nodeConf;

        public ServicesConnectionImpl(List<NodeConfig> configList)
        {
            //
            // find a node to connect to
            //
            // TODO: this should start at a random point in the list

            int start = 0;
            for (int i = 0; i != configList.size(); i++)
            {
                int nodeNo = (start + i) % configList.size();

                nodeConf = configList.get(nodeNo);

                if (nodeConf.getThrowable() == null)
                {
                    if (getConnection() == null)
                    {
                        continue;
                    }
                }
            }
        }

        private synchronized NodeServicesConnection resetConnection()
        {
            // TODO: need to look into possible connection leakage here. 2 threads may end up trying to reset at the same time.
            connection = null;

            return getConnection();
        }

        private synchronized NodeServicesConnection getConnection()
        {
            if (connection == null)
            {
                try
                {
                    connection = new NodeServicesConnection(nodeConf);
                }
                catch (IOException e)
                {
                    // TODO:
                }
            }

            return connection;
        }

        public Capability[] getCapabilities()
        {
            return getConnection().getCapabilities();
        }

        public MessageReply sendMessage(MessageType type, ASN1Encodable messagePayload)
            throws ServiceConnectionException
        {
            try
            {
                return getConnection().sendMessage(type, messagePayload);
            }
            catch (Exception e)
            {
                return resetConnection().sendMessage(type, messagePayload);
            }
        }
    }

    private static class AdminServicesConnectionImpl
        implements AdminServicesConnection
    {
        private Map<String, NodeServicesConnection> connectionMap = new HashMap<String, NodeServicesConnection>();
        private Set<Capability> capabilitySet = new HashSet<Capability>();

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

        public Capability[] getCapabilities()
        {
            return capabilitySet.toArray(new Capability[capabilitySet.size()]);
        }

        public MessageReply sendMessage(MessageType type, ASN1Encodable messagePayload)
            throws ServiceConnectionException
        {
            return connectionMap.get(connectionMap.keySet().iterator().next()).sendMessage(type, messagePayload);
        }

        @Override
        public Set<String> getActiveNodeNames()
        {
            // TODO: this should only return names with an active connection
            return connectionMap.keySet();
        }

        public MessageReply sendMessage(String nodeName, MessageType type, ASN1Encodable messagePayload)
            throws ServiceConnectionException
        {
            return connectionMap.get(nodeName).sendMessage(type, messagePayload);
        }
    }
}
