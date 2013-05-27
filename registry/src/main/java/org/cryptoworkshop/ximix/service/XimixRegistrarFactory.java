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
package org.cryptoworkshop.ximix.service;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.conf.ConfigException;
import org.cryptoworkshop.ximix.common.conf.ConfigObjectFactory;
import org.cryptoworkshop.ximix.crypto.KeyService;
import org.cryptoworkshop.ximix.crypto.SigningService;
import org.cryptoworkshop.ximix.crypto.impl.SigningServiceImpl;
import org.cryptoworkshop.ximix.upload.UploadService;
import org.cryptoworkshop.ximix.upload.impl.UploadServiceImpl;
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
                //
                // find a MixNet node to connect to
                //
                // TODO: this should start at a random point in the list
                int start = 0;
                for (int i = 0; i != nodes.size(); i++)
                {
                    int nodeNo = (start + i) % nodes.size();
                    final NodeConfig nodeConf = nodes.get(nodeNo);

                    if (nodeConf.getThrowable() == null)
                    {
                        Object service = null;

                        if (serviceClass.isAssignableFrom(UploadService.class))
                        {
                            try
                            {
                                service = new UploadServiceImpl(nodeConf.getAddress(), nodeConf.getPortNo());
                            }
                            catch (IOException e)
                            {
                                continue;
                            }
                        }
                        else if (serviceClass.isAssignableFrom(KeyService.class))
                        {
                            service = new SigningServiceImpl();
                        }
                        else if (serviceClass.isAssignableFrom(SigningService.class))
                        {
                            service = new SigningServiceImpl();
                        }

                        return (T)service;
                    }
                }

                throw new RegistrarServiceException("Unable to identify service");
            }
        };
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
}
