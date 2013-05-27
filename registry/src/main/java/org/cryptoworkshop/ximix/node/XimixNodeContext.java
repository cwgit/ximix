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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.conf.ConfigException;
import org.cryptoworkshop.ximix.common.conf.ConfigObjectFactory;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.service.Service;
import org.cryptoworkshop.ximix.common.service.ServiceContext;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class XimixNodeContext
    implements ServiceContext
{
    private Executor boardUpdateExecutor = Executors.newSingleThreadExecutor();
    private Executor multiTaskExecutor = Executors.newCachedThreadPool();

    private List<Service> services = new ArrayList<Service>();

    public XimixNodeContext(Config nodeConfig)
        throws ConfigException
    {
        nodeConfig.getConfigObjects("services", new NodeConfigFactory());
    }

    public void addConnection(Runnable task)
    {
        multiTaskExecutor.execute(task);
    }

    public void scheduleTask(Runnable task)
    {
        multiTaskExecutor.execute(task);
    }

    public Service getService(Message.Type type)
    {
        for (Service service : services)
        {
            if (service.isAbleToHandle(type))
            {
                return service;
            }
        }

        return null;
    }

    private class NodeConfig
    {
        private int portNo;
        private Exception throwable;

        NodeConfig(Node configNode)
        {
            NodeList xmlNodes = configNode.getChildNodes();

            for (int i = 0; i != xmlNodes.getLength(); i++)
            {
                Node xmlNode = xmlNodes.item(i);

                if (xmlNode.getNodeName().equals("service"))
                {
                    try
                    {
                        Class clazz = Class.forName(xmlNode.getTextContent());

                        Constructor constructor = clazz.getConstructor(ServiceContext.class);

                        services.add((Service)constructor.newInstance(XimixNodeContext.this));
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

        public int getPortNo()
        {
            return portNo;
        }
    }

    private class NodeConfigFactory
        implements ConfigObjectFactory<NodeConfig>
    {
        public NodeConfig createObject(Node configNode)
        {
            return new NodeConfig(configNode);
        }
    }
}
