package org.cryptoworkshop.ximix.node;

import org.bouncycastle.asn1.DEROutputStream;
import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.conf.ConfigException;
import org.cryptoworkshop.ximix.common.handlers.ThrowableHandler;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;

import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A default ximix node implementation.
 */
public class DefaultXimixNode
    implements XimixNode
{
    private final Config nodeConfig;
    private final XimixNodeContext nodeContext;
    private final AtomicBoolean stopped = new AtomicBoolean(false);
    private final int portNo;
    private final ThrowableHandler exceptionHandler;
    private ServerSocket ss = null;


    public DefaultXimixNode(Config config, Map<String, ServicesConnection> servicesMap, ThrowableHandler exceptionHandler)
        throws ConfigException
    {
        this.nodeConfig = config;
        this.portNo = nodeConfig.getIntegerProperty("portNo");
        this.nodeContext = new XimixNodeContext(servicesMap, nodeConfig);
        this.exceptionHandler = exceptionHandler;
    }

    public void start()
    {
        try
        {
            ss = new ServerSocket(portNo);

            ss.setSoTimeout(1000);                       // TODO: should be a config item

            while (!stopped.get())
            {
                try
                {
                    Socket s = ss.accept();

                    if (!stopped.get())
                    {
                        nodeContext.addConnection(new XimixServices(nodeContext, s).withThrowableHandler(exceptionHandler));
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
        catch (Exception e)
        {
            exceptionHandler.handle(e);
        }
    }

    @Override
    public boolean shutdown(int timeout, TimeUnit unit)
        throws InterruptedException
    {
        stopped.set(true);
        try
        {
            ss.close();
        }
        catch (IOException e)
        {

        }
        return nodeContext.shutdown(timeout, unit);
    }

    /**
     * @param s
     * @throws Exception
     */
    protected void respondExiting(Socket s)
        throws Exception
    {

        OutputStream sOut = s.getOutputStream();

        DEROutputStream aOut = new DEROutputStream(sOut);
        // TODO: NodeInfo actually is the first object in the protocol
        aOut.writeObject(new MessageReply(MessageReply.Type.EXITING));
        aOut.flush();
        aOut.close();

        s.close();

    }
}
