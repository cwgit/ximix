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

import java.io.File;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.conf.ConfigException;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;
import org.cryptoworkshop.ximix.common.util.ExtendedFuture;
import org.cryptoworkshop.ximix.common.util.FutureComplete;
import org.cryptoworkshop.ximix.registrar.RegistrarConnectionException;
import org.cryptoworkshop.ximix.registrar.XimixRegistrarFactory;

public class XimixNodeFactory
{

    public static XimixNode createNode(InputStream peersConfig, InputStream config)  throws RegistrarConnectionException, ConfigException
    {
        Map<String, ServicesConnection> servicesMap = XimixRegistrarFactory.createServicesRegistrarMap(peersConfig);
        XimixNode node = new XimixNodeImpl(servicesMap,new Config(config));
        return node;
    }

    public static XimixNode createNode(final File peersConfig, final File config)
            throws RegistrarConnectionException, ConfigException
    {
        final Map<String, ServicesConnection> servicesMap = XimixRegistrarFactory.createServicesRegistrarMap(peersConfig);


        XimixNode node = new XimixNodeImpl(servicesMap,config);

        return node;

//        return new XimixNode()
//        {
//            private final Config nodeConfig = new Config(config);
//
//            private final XimixNodeContext nodeContext = new XimixNodeContext(servicesMap, nodeConfig);
//
//            final int portNo = nodeConfig.getIntegerProperty("portNo");
//
//            public void start()
//            {
//                boolean stop = false;
//
//                try
//                {
//                    ServerSocket ss = new ServerSocket(portNo);
//
//                    while (!stop)
//                    {
//                        Socket s = ss.accept();
//
//                        nodeContext.addConnection(new XimixServices(nodeContext, s));
//                    }
//                } catch (IOException e)
//                {
//                    e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
//                }
//            }
//
//
//            @Override
//            public StopFuture stop(int timeout, TimeUnit unit)
//            {
//                return nodeContext.signalShutdown(timeout, unit);
//            }
//        };
    }

    /**
     *
     */
    protected static class XimixNodeImpl implements XimixNode
    {
        private Map<String, ServicesConnection> servicesMap = null;
        private Config nodeConfig = null;
        private XimixNodeContext nodeContext = null;
        private int portNo = 1234;
        private ThrowableHandler unhandledThrowableHandler = null;

        public XimixNodeImpl(Map<String, ServicesConnection> servicesMap, File config) throws ConfigException, RegistrarConnectionException
        {
            this.nodeConfig = new Config(config);
            this.servicesMap = servicesMap;
            nodeContext = new XimixNodeContext(servicesMap, nodeConfig);
            portNo = nodeConfig.getIntegerProperty("portNo");
        }

        public XimixNodeImpl(Map<String, ServicesConnection> servicesMap, Config config) throws ConfigException, RegistrarConnectionException
        {
            this.nodeConfig = config;
            this.servicesMap = servicesMap;
            nodeContext = new XimixNodeContext(servicesMap, nodeConfig);
            portNo = nodeConfig.getIntegerProperty("portNo");
        }


        @Override
        public void start()
        {
            boolean stop = false;
            try
            {
                ServerSocket ss = new ServerSocket(portNo);
                while (!stop)
                {
                    Socket s = ss.accept();
                    nodeContext.addConnection(new XimixServices(nodeContext, s));
                }
            } catch (Exception e)
            {
                if (unhandledThrowableHandler != null)
                {
                    unhandledThrowableHandler.throwable(e);
                } else
                {
                    e.printStackTrace();
                }
            }
        }

        @Override
        public ExtendedFuture stop(int timeout, TimeUnit unit, FutureComplete handler)
        {
            return nodeContext.signalShutdown(timeout, unit, handler);
        }

        public Map<String, ServicesConnection> getServicesMap()
        {
            return servicesMap;
        }

        public void setServicesMap(Map<String, ServicesConnection> servicesMap)
        {
            this.servicesMap = servicesMap;
        }

        public Config getNodeConfig()
        {
            return nodeConfig;
        }

        public void setNodeConfig(Config nodeConfig)
        {
            this.nodeConfig = nodeConfig;
        }

        public XimixNodeContext getNodeContext()
        {
            return nodeContext;
        }

        public void setNodeContext(XimixNodeContext nodeContext)
        {
            this.nodeContext = nodeContext;
        }

        public int getPortNo()
        {
            return portNo;
        }

        public void setPortNo(int portNo)
        {
            this.portNo = portNo;
        }

        public ThrowableHandler getUnhandledThrowableHandler()
        {
            return unhandledThrowableHandler;
        }

        public void setUnhandledThrowableHandler(ThrowableHandler unhandledThrowableHandler)
        {
            this.unhandledThrowableHandler = unhandledThrowableHandler;
        }
    }



}
