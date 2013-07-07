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
package org.cryptoworkshop.ximix.console;

import java.io.File;
import java.security.SecureRandom;
import java.util.List;

import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.console.config.ConsoleConfig;
import org.cryptoworkshop.ximix.console.config.ConsoleConfigFactory;
import org.cryptoworkshop.ximix.console.handlers.ConsoleHandler;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.ResourceHandler;

/**
 *
 */
public class Main
{

    private static Integer port = 1887;
    private static String localAddress = "127.0.0.1";
    private static String configSource = null;
    private static SecureRandom secureRandom = new SecureRandom();
    private static Config config = null;

    /**
     * Main.
     *
     * @param args command line arguments.
     * @throws Exception Rethrows all exceptions.
     */
    public static void main(String[] args) throws Exception
    {
        if (args.length == 0)
        {
            System.err.println("No configuration file specified.");
            System.exit(-1);
        }

        init(args);

    }

    public static void init(String[] args) throws Exception
    {

        config = new Config(new File(args[0]));

        config.getConfigObjects("console", new ConsoleConfigFactory());


        try
        {
            List<ConsoleConfig> consoleConfig = config.getConfigObjects("console", ConsoleConfigFactory.factory());

            //
            // Do all but the last.
            //
            for (int t = 0; t < consoleConfig.size() - 1; t++)
            {
                start(consoleConfig.get(t), false);
            }

            //
            // Start the last one and join.
            //
            start(consoleConfig.get(consoleConfig.size()-1),true);

        } catch (Exception e)
        {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }

    }



    public static SecureRandom random()
    {
        return secureRandom;
    }

    public static void start(ConsoleConfig config, boolean join) throws Exception
    {


//        if (port == null)
//        {
//            p = Config.config().getProperty("console.bind.port", 1887);
//        } else
//        {
//            p = port;
//        }
//
//        if (localAddress == null)
//        {
//            b = Config.config().getProperty("console.bind.host", "0.0.0.0");
//        } else
//        {
//            b = localAddress;
//        }


        Server server = new Server(config.getHttpConfig().getPort());
        ServerConnector connector = new ServerConnector(server);
        connector.setHost(config.getHttpConfig().getHost());
        ContextHandler rpcHandler = new ContextHandler("/api");
        rpcHandler.setClassLoader(Thread.currentThread().getContextClassLoader());
        rpcHandler.setHandler(new ConsoleHandler(config));

        ResourceHandler staticHandler = new ResourceHandler();
        staticHandler.setResourceBase(ConsoleHandler.class.getResource("/html").toURI().toString());

        HandlerList handlers = new HandlerList();
        handlers.setHandlers(new Handler[]{rpcHandler, staticHandler});
        server.setHandler(handlers);

        server.start();
        if (join)
        {
            server.join();
        }
    }


}
