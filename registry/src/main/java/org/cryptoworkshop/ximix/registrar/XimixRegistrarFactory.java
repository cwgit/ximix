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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.conf.ConfigException;
import org.cryptoworkshop.ximix.common.conf.ConfigObjectFactory;
import org.cryptoworkshop.ximix.common.message.ClientMessage;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.MessageType;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.crypto.client.KeyService;
import org.cryptoworkshop.ximix.crypto.client.SigningService;
import org.cryptoworkshop.ximix.crypto.client.ClientSigningService;
import org.cryptoworkshop.ximix.mixnet.client.ClientUploadService;
import org.cryptoworkshop.ximix.mixnet.client.UploadService;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class XimixRegistrarFactory
{
    public static XimixRegistrar createServicesRegistrar(File config)
        throws ConfigException, RegistrarConnectionException
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

    public static Map<String, SpecificXimixRegistrar> createServicesRegistrarMap(File config)
        throws ConfigException, RegistrarConnectionException
    {
        final List<NodeConfig> nodes = new Config(config).getConfigObjects("node", new NodeConfigFactory());
        Map <String, SpecificXimixRegistrar> rMap = new HashMap<String, SpecificXimixRegistrar>();

        for (int i = 0; i != nodes.size(); i++)
        {
            NodeConfig node = nodes.get(i);

            // TODO: this needs to be fetched from a certificate
            final String name = Integer.toString(node.getPortNo());
            final List<NodeConfig> thisNode = Collections.singletonList(node);

            SpecificXimixRegistrar r = new SpecificXimixRegistrar()
            {
                public <T> T connect(Class<T> serviceClass)
                    throws RegistrarServiceException
                {
                    if (serviceClass.isAssignableFrom(UploadService.class))
                    {
                        return (T)new ClientUploadService(new ServicesConnectionImpl(thisNode));
                    }
                    else if (serviceClass.isAssignableFrom(KeyService.class))
                    {
                        return (T)new ClientSigningService(new ServicesConnectionImpl(thisNode));
                    }
                    else if (serviceClass.isAssignableFrom(SigningService.class))
                    {
                        return (T)new ClientSigningService(new ServicesConnectionImpl(thisNode));
                    }

                    throw new RegistrarServiceException("Unable to identify service");
                }

                public String getNodeName()
                {
                    return name;
                }
            };

            rMap.put(name, r);
        }

        return rMap;
    }

    private static class NodeConfig
    {
        private InetAddress address;
        private int portNo;
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
    }

    private static class NodeConfigFactory
        implements ConfigObjectFactory<NodeConfig>
    {
        public NodeConfig createObject(Node configNode)
        {
            return new NodeConfig(configNode);
        }
    }

    private static class ServicesConnectionImpl
        implements ServicesConnection
    {
        private Socket connection;
        private InputStream cIn;
        private OutputStream cOut;

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
                final NodeConfig nodeConf = configList.get(nodeNo);

                if (nodeConf.getThrowable() == null)
                {
                    // TODO: we should query each node to see what it's capabilities are.
                    try
                    {
                        this.connection = new Socket(nodeConf.getAddress(), nodeConf.getPortNo());
                        break;
                    }
                    catch (IOException e)
                    {
                        continue;
                    }
                }
            }

            if (connection != null)
            {
                try
                {
                    cOut = connection.getOutputStream();
                    cIn = connection.getInputStream();
                }
                catch (IOException e)
                {
                    e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                }

            }
        }

        public MessageReply sendMessage(MessageType type, ASN1Encodable messagePayload)
            throws ServiceConnectionException
        {
            try
            {
                cOut.write(new ClientMessage((ClientMessage.Type)type, messagePayload).getEncoded());

                return MessageReply.getInstance(new ASN1InputStream(cIn, 30000).readObject());      // TODO
            }
            catch (Exception e)
            {                                     e.printStackTrace();
                // TODO: this should only happen when we've run out of nodes.
                throw new ServiceConnectionException("couldn't send");
            }
        }

        public MessageReply sendThresholdMessage(MessageType type, ASN1Encodable messagePayload)
            throws ServiceConnectionException
        {
            try
            {
                cOut.write(new ClientMessage((ClientMessage.Type)type, messagePayload).getEncoded());

                return MessageReply.getInstance(new ASN1InputStream(cIn).readObject());
            }
            catch (Exception e)
            {                                         e.printStackTrace();
                // TODO: this should only happen when we've run out of nodes.
                throw new ServiceConnectionException("couldn't send");
            }
        }
    }
}
