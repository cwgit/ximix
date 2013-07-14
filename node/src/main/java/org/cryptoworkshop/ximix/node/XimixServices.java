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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROutputStream;
import org.cryptoworkshop.ximix.common.handlers.ThrowableListener;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.NodeInfo;
import org.cryptoworkshop.ximix.common.service.Service;

class XimixServices
    implements Runnable
{
    static class Builder
    {
        private final XimixNodeContext nodeContext;

        private ThrowableListener throwableListener = XimixNodeBuilder.throwableListener;

        Builder(XimixNodeContext nodeContext)
        {
            this.nodeContext = nodeContext;
        }

        /**
         * Set a throwable handler for any uncaught exceptions.
         *
         * @param throwableListener The listener, may be null.
         * @return the current builder.
         */
        public Builder withThrowableListener(ThrowableListener throwableListener)
        {
            if (throwableListener != null)
            {
                this.throwableListener = throwableListener;
            }
            else
            {
                this.throwableListener = XimixNodeBuilder.throwableListener;
            }

            return this;
        }

        public XimixServices build(Socket s)
        {
            return new XimixServices(nodeContext, s, throwableListener);
        }
    }

    private final Socket s;
    private final XimixNodeContext nodeContext;
    private final ThrowableListener throwableHandler;

    private final AtomicBoolean stopped = new AtomicBoolean(false);

    private int maxInputSize = 32 * 1024;  //TODO should be config item.

    private XimixServices(XimixNodeContext nodeContext, Socket s, ThrowableListener throwableHandler)
    {
        this.s = s;
        this.nodeContext = nodeContext;
        this.throwableHandler = throwableHandler;
    }

    public void run()
    {
        try
        {
            s.setSoTimeout(15000);    // TODO: should be a config item

            InputStream sIn = s.getInputStream();
            OutputStream sOut = s.getOutputStream();

            ASN1InputStream aIn = new ASN1InputStream(sIn, maxInputSize);       // TODO: should be a config item
            DEROutputStream aOut = new DEROutputStream(sOut);

            aOut.writeObject(new NodeInfo(nodeContext.getName(), nodeContext.getCapabilities()));

            while (!stopped.get())
            {
                try
                {
                    //System.out.println("Connection from: "+s.getRemoteSocketAddress())
                    Object o;

                    while ((o = aIn.readObject()) != null && !nodeContext.isStopCalled())
                    {
                        Message message = Message.getInstance(o);

                        Service service = nodeContext.getService(message);
                        System.err.println("message received: " + message.getType() + " " + service);
                        MessageReply reply = service.handle(message);

                        System.err.println("message received: " + reply);
                        aOut.writeObject(reply);
                    }

                    // if we are here we've either had a null (eof) of isStopCalled is true
                    // we exit the loop
                    // TODO: log if node stopped or client hung up
                    break;
                }
                catch (SocketTimeoutException e)
                {
                    continue;
                }
            }
        }
        catch (IOException e)
        {
            throwableHandler.notify(e);
        }
    }

    public void stop()
    {
        stopped.set(true);
    }
}
