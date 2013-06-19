package org.cryptoworkshop.ximix.console;

import org.cryptoworkshop.ximix.console.handlers.ConsoleHandler;
import org.cryptoworkshop.ximix.console.util.Config;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.ResourceHandler;

import java.io.File;
import java.net.URL;
import java.security.SecureRandom;

/**
 *
 */
public class Main {

    private static Integer port = null;
    private static String localAddress = null;
    private static String configSource = null;
    private static SecureRandom secureRandom = new SecureRandom();

    /**
     * Main.
     *
     * @param args command line arguments.
     * @throws Exception Rethrows all exceptions.
     */
    public static void main(String[] args) throws Exception {
        init(args);
        start(true);

    }

    public static void init(String[] args) throws Exception {
        for (int t = 0; t < args.length; t++) {
            String cmd = args[t];
            if ("--host".equals(cmd)) {
                assertExists("Host is not defined.", t, args);
                localAddress = args[++t];
                continue;
            }

            if ("--port".equals(cmd)) {
                port = nextInteger("Invalid port", ++t, args, 0, 65535);
                continue;
            }

            if ("--config".equals(cmd)) {
                assertExists("Config source is not defined.", t, args);

                String cfg = args[++t];

                if (cfg.startsWith("http") || cfg.startsWith("file")) {
                    Config.load(new URL(cfg));
                } else { // Treat as local file.
                    Config.load(new File(cfg));
                }
            }
        }
    }

    private static void assertExists(String error, int t, String[] args) {
        if (t >= args.length) {
            System.err.println(error);
            System.exit(-1);
        }
    }

    private static Integer nextInteger(String error, int t, String[] args, Integer notBefore, Integer notAfter) {
        if (t >= args.length) {
            System.err.println(error);
            System.exit(-1);
        }

        int out = 0;
        try {
            out = Integer.valueOf(args[t].trim());
        } catch (NumberFormatException ex) {
            System.err.println(error);
            System.err.println(ex.getMessage());
            System.exit(-1);
        }

        if (notBefore != null) {
            if (out < notBefore) {
                System.err.println(error);
                System.err.println(out + " is less than " + notBefore);
                System.exit(-1);
            }
        }

        if (notAfter != null && out > notAfter) {
            System.err.println(error);
            System.err.println(out + " is greater than " + notAfter);
            System.exit(-1);

        }

        return out;
    }

    public static SecureRandom random() {
        return secureRandom;
    }

    public static void start(boolean join) throws Exception {

        int p = 1887;
        String b = "0.0.0.0";


        if (port == null) {
            p = Config.config().getProperty("console.bind.port", 1887);
        } else {
            p = port;
        }

        if (localAddress == null) {
            b = Config.config().getProperty("console.bind.host", "0.0.0.0");
        } else {
            b = localAddress;
        }


        Server server = new Server(p);
        ServerConnector connector = new ServerConnector(server);
        connector.setHost(b);
        ContextHandler rpcHandler = new ContextHandler("/api");
        rpcHandler.setClassLoader(Thread.currentThread().getContextClassLoader());
        rpcHandler.setHandler(new ConsoleHandler());

        ResourceHandler staticHandler = new ResourceHandler();
        staticHandler.setResourceBase(ConsoleHandler.class.getResource("/html").toURI().toString());

        HandlerList handlers = new HandlerList();
        handlers.setHandlers(new Handler[]{rpcHandler, staticHandler});
        server.setHandler(handlers);

        server.start();
        if (join) {
            server.join();
        }
    }


}
