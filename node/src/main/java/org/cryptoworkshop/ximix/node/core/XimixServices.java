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
package org.cryptoworkshop.ximix.node.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROutputStream;
import org.cryptoworkshop.ximix.common.asn1.message.Message;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.NodeInfo;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.node.service.NodeService;

class XimixServices
    implements Runnable
{
    static class Builder
    {
        private final XimixNodeContext nodeContext;

        private EventNotifier eventNotifier;

        Builder(XimixNodeContext nodeContext)
        {
            this.nodeContext = nodeContext;
            this.eventNotifier = nodeContext.getEventNotifier();
        }

        /**
         * Set a throwable handler for any uncaught exceptions.
         *
         * @param eventNotifier The listener, may be null.
         * @return the current builder.
         */
        public Builder withThrowableListener(EventNotifier eventNotifier)
        {
            if (eventNotifier != null)
            {
                this.eventNotifier = eventNotifier;
            }
            else
            {
                this.eventNotifier = nodeContext.getEventNotifier();
            }

            return this;
        }

        public XimixServices build(Socket s)
        {
            return new XimixServices(nodeContext, s, eventNotifier);
        }
    }

    private final Socket s;
    private final XimixNodeContext nodeContext;
    private final EventNotifier throwableHandler;

    private final AtomicBoolean stopped = new AtomicBoolean(false);

    private int maxInputSize = 32 * 1024;  //TODO should be config item.

    private XimixServices(XimixNodeContext nodeContext, Socket s, EventNotifier throwableHandler)
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

                        NodeService nodeService = nodeContext.getService(message);
                        nodeContext.getEventNotifier().notify(EventNotifier.Level.ERROR, "Received Message: " + message.getType());
                        MessageReply reply = nodeService.handle(message);

                        nodeContext.getEventNotifier().notify(EventNotifier.Level.DEBUG, "Reply Message: " + reply);
                        aOut.writeObject(reply);
                    }

                    nodeContext.getEventNotifier().notify(EventNotifier.Level.INFO, "Service connection on " + nodeContext.getName() + " shutdown, stop called = " + nodeContext.isStopCalled());
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
            throwableHandler.notify(EventNotifier.Level.WARN, e);
        }
    }

    public void stop()
    {
        stopped.set(true);
    }
}
