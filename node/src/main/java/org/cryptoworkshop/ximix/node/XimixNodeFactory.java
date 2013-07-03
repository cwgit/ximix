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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROutputStream;
import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.conf.ConfigException;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;
import org.cryptoworkshop.ximix.registrar.RegistrarConnectionException;
import org.cryptoworkshop.ximix.registrar.XimixRegistrarFactory;

public class XimixNodeFactory
{
    public static XimixNode createNode(final File peersConfig, final File config)
        throws RegistrarConnectionException, ConfigException, FileNotFoundException
    {
        return createNode(new FileInputStream(peersConfig), new FileInputStream(config));
    }

    public static XimixNode createNode(InputStream peersConfig, final InputStream config)
        throws RegistrarConnectionException, ConfigException
    {
        final Map<String, ServicesConnection> servicesMap = XimixRegistrarFactory.createServicesRegistrarMap(peersConfig);

        return new XimixNode()
        {
            private final Config nodeConfig = new Config(config);

            private final XimixNodeContext nodeContext = new XimixNodeContext(servicesMap, nodeConfig);
            private final AtomicBoolean    stopped = new AtomicBoolean(false);
            private final int portNo = nodeConfig.getIntegerProperty("portNo");

            public void start()
            {
                try
                {
                    ServerSocket ss = new ServerSocket(portNo);

                    ss.setSoTimeout(1000);                       // TODO: should be a config item

                    while (!stopped.get())
                    {
                        try
                        {
                            Socket s = ss.accept();

                            if (!stopped.get())
                            {
                                nodeContext.addConnection(new XimixServices(nodeContext, s));
                            }
                            else
                            {
                                respondExiting(s);  // this can only happen once, but at least we're been polite...
                            }
                        }
                        catch (SocketTimeoutException e)
                        {
                            continue;
                        }
                    }
                }
                catch (IOException e)
                {
                    e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                }
            }

            @Override
            public boolean shutdown(int timeout, TimeUnit unit)
                throws InterruptedException
            {
                stopped.set(true);

                return nodeContext.shutdown(timeout, unit);
            }
        };
    }

    private static void respondExiting(Socket s)
    {
        try
        {
            OutputStream sOut = s.getOutputStream();

            DEROutputStream aOut = new DEROutputStream(sOut);
           // TODO: NodeInfo actually is the first object in the protocol
            aOut.writeObject(new MessageReply(MessageReply.Type.EXITING));
            aOut.flush();
            aOut.close();

            s.close();
        }
        catch (Exception ex)
        {
            //TODO logging.
            ex.printStackTrace();
        }
    }
    /**
     *
     */
//    protected static class XimixNodeImpl implements XimixNode
//    {
//        private Map<String, ServicesConnection> servicesMap = null;
//        private Config nodeConfig = null;
//        private XimixNodeContext nodeContext = null;
//        private int portNo = 1234;
//        private ThrowableHandler unhandledThrowableHandler = null;
//        private boolean stop = false;
//
//
//        public XimixNodeImpl(Map<String, ServicesConnection> servicesMap, File config) throws ConfigException, RegistrarConnectionException
//        {
//            this.nodeConfig = new Config(config);
//            this.servicesMap = servicesMap;
//            nodeContext = new XimixNodeContext(servicesMap, nodeConfig);
//            portNo = nodeConfig.getIntegerProperty("portNo");
//        }
//
//        public XimixNodeImpl(Map<String, ServicesConnection> servicesMap, Config config) throws ConfigException, RegistrarConnectionException
//        {
//            this.nodeConfig = config;
//            this.servicesMap = servicesMap;
//            nodeContext = new XimixNodeContext(servicesMap, nodeConfig);
//            portNo = nodeConfig.getIntegerProperty("portNo");
//        }
//
//        @Override
//        public void start()
//        {
//
//            try
//            {
//                ServerSocket ss = new ServerSocket(portNo);
//                ss.setSoTimeout(1000);
//
//                while (!stop)
//                {
//                    Socket s = null;
//                    try
//                    {
//                        s = ss.accept();
//
//                        if (!stop)
//                        {
//                            nodeContext.addConnection(new XimixServices(nodeContext, s));
//                        }
//                    }
//                    catch (SocketTimeoutException ste)
//                    {
//                       // Deliberately ignored.. //TODO suggest move to NIO and selectors for the accept part.
//                    }
//                }
//
//                ss.close();
//            }
//            catch (Exception e)
//            {
//                if (unhandledThrowableHandler != null)
//                {
//                    unhandledThrowableHandler.throwable(e);
//                } else
//                {
//                    e.printStackTrace();
//                }
//            }
//        }
//
//        @Override
//        public ExtendedFuture stop(int timeout, TimeUnit unit, FutureComplete handler)
//        {
//            stop = true;
//
//            return nodeContext.signalShutdown(timeout, unit, handler);
//        }
//
//        public Map<String, ServicesConnection> getServicesMap()
//        {
//            return servicesMap;
//        }
//
//        public void setServicesMap(Map<String, ServicesConnection> servicesMap)
//        {
//            this.servicesMap = servicesMap;
//        }
//
//        public Config getNodeConfig()
//        {
//            return nodeConfig;
//        }
//
//        public void setNodeConfig(Config nodeConfig)
//        {
//            this.nodeConfig = nodeConfig;
//        }
//
//        public XimixNodeContext getNodeContext()
//        {
//            return nodeContext;
//        }
//
//        public void setNodeContext(XimixNodeContext nodeContext)
//        {
//            this.nodeContext = nodeContext;
//        }
//
//        public int getPortNo()
//        {
//            return portNo;
//        }
//
//        public void setPortNo(int portNo)
//        {
//            this.portNo = portNo;
//        }
//
//        public ThrowableHandler getUnhandledThrowableHandler()
//        {
//            return unhandledThrowableHandler;
//        }
//
//        public void setUnhandledThrowableHandler(ThrowableHandler unhandledThrowableHandler)
//        {
//            this.unhandledThrowableHandler = unhandledThrowableHandler;
//        }
//    }
//

}
