package org.cryptoworkshop.ximix.console;

import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.console.handlers.ConsoleHandler;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.ResourceHandler;

import java.io.File;
import java.security.SecureRandom;

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
        start(true);

    }

    public static void init(String[] args) throws Exception
    {

        config = new Config(new File(args[0]));

        localAddress = config.getStringProperty("http.bind-host", localAddress);
        port = config.getIntegerProperty("http.bind-port", port);

    }

    private static void assertExists(String error, int t, String[] args)
    {
        if (t >= args.length)
        {
            System.err.println(error);
            System.exit(-1);
        }
    }

    private static Integer nextInteger(String error, int t, String[] args, Integer notBefore, Integer notAfter)
    {
        if (t >= args.length)
        {
            System.err.println(error);
            System.exit(-1);
        }

        int out = 0;
        try
        {
            out = Integer.valueOf(args[t].trim());
        } catch (NumberFormatException ex)
        {
            System.err.println(error);
            System.err.println(ex.getMessage());
            System.exit(-1);
        }

        if (notBefore != null)
        {
            if (out < notBefore)
            {
                System.err.println(error);
                System.err.println(out + " is less than " + notBefore);
                System.exit(-1);
            }
        }

        if (notAfter != null && out > notAfter)
        {
            System.err.println(error);
            System.err.println(out + " is greater than " + notAfter);
            System.exit(-1);

        }

        return out;
    }

    public static SecureRandom random()
    {
        return secureRandom;
    }

    public static void start(boolean join) throws Exception
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


        Server server = new Server(port);
        ServerConnector connector = new ServerConnector(server);
        connector.setHost(localAddress);
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
