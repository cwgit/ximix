package org.cryptoworkshop.ximix.node;

import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.DEROutputStream;
import org.cryptoworkshop.ximix.common.config.Config;
import org.cryptoworkshop.ximix.common.config.ConfigException;
import org.cryptoworkshop.ximix.common.handlers.ThrowableListener;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;

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
    private final ThrowableListener throwableListener;
    private ServerSocket ss = null;

    DefaultXimixNode(Config config, Map<String, ServicesConnection> servicesMap, ThrowableListener throwableListener)
        throws ConfigException
    {
        this.nodeConfig = config;
        this.portNo = nodeConfig.getIntegerProperty("portNo");
        this.nodeContext = new XimixNodeContext(servicesMap, nodeConfig);
        this.throwableListener = throwableListener;
    }

    public void start()
    {
        try
        {
            ss = new ServerSocket(portNo);

            ss.setSoTimeout(1000);                       // TODO: should be a config item

            XimixServices.Builder servicesBuilder = new XimixServices.Builder(nodeContext).withThrowableListener(throwableListener);

            while (!stopped.get())
            {
                try
                {
                    Socket s = ss.accept();

                    if (!stopped.get())
                    {
                        nodeContext.addConnection(servicesBuilder.build(s));
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
            throwableListener.notify(e);
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
