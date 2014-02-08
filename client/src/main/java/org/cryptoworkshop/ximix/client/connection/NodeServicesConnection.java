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
package org.cryptoworkshop.ximix.client.connection;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ClientMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ErrorMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.MessageType;
import org.cryptoworkshop.ximix.common.asn1.message.NodeInfo;
import org.cryptoworkshop.ximix.common.util.EventNotifier;

/**
 * Internal implementation of a named ServicesConnection. This class ties a connection back to a specific node.
 */
class NodeServicesConnection
    implements SpecificServicesConnection
{
    private final EventNotifier eventNotifier;
    private final InetAddress address;
    private final int portNo;
    private final NodeConnectionListener listener;

    private final AtomicBoolean isShutdown = new AtomicBoolean(false);
    private final AtomicBoolean isTryingToConnect = new AtomicBoolean(false);
    private final String name;

    private NodeInfo nodeInfo;
    private Socket connection;
    private InputStream cIn;
    private OutputStream cOut;

    public NodeServicesConnection(NodeConfig config, NodeConnectionListener listener, EventNotifier eventNotifier)
    {
        this.name = config.getName();
        this.eventNotifier = eventNotifier;
        this.address = config.getAddress();
        this.portNo = config.getPortNo();
        this.listener = listener;
    }

    public synchronized void activate()
        throws ServiceConnectionException
    {
        buildConnection();
    }

    @Override
    public synchronized void shutdown()
        throws ServiceConnectionException
    {
        isShutdown.set(true);

        close();
    }

    public String getName()
    {
        return name;
    }

    public synchronized CapabilityMessage[] getCapabilities()
        throws ServiceConnectionException
    {
        if (connection == null)
        {
            if (!isTryingToConnect.get())
            {
                buildConnection();
            }
            else
            {
                return new CapabilityMessage[0];
            }
        }

        return nodeInfo.getCapabilities();
    }

    @Override
    public EventNotifier getEventNotifier()
    {
        return eventNotifier;
    }

    public synchronized MessageReply sendMessage(MessageType type, ASN1Encodable messagePayload)
        throws ServiceConnectionException
    {
        // maybe we're down?
        if (isTryingToConnect.get())
        {
            return new MessageReply(MessageReply.Type.ERROR, new ErrorMessage("Link to node " + name +  " unavailable"));
        }

        // if there is an error we do one retry to rebuild the line before exiting.
        for (int i = 0; i != 2; i++)
        {
            if (connection == null)
            {
                buildConnection();
            }

            byte[] encodedMessage;

            try
            {
                if (type instanceof ClientMessage.Type)
                {
                    encodedMessage = new ClientMessage((ClientMessage.Type)type, messagePayload).getEncoded();

                }
                else
                {
                    encodedMessage = new CommandMessage((CommandMessage.Type)type, messagePayload).getEncoded();
                }
            }
            catch (IOException e)
            {
                throw new ServiceConnectionException("Malformed message: " + e.getMessage(), e);
            }

            try
            {
                cOut.write(encodedMessage);

                return MessageReply.getInstance(new ASN1InputStream(cIn, 300000).readObject());      // TODO
            }
            catch (Exception e)
            {
                try
                {
                    this.shutdown();
                }
                catch (Exception ex)
                {
                    eventNotifier.notify(EventNotifier.Level.WARN, "Exception resetting link to " + address + ": " + e.getMessage(), e);
                }

                eventNotifier.notify(EventNotifier.Level.WARN, "Unable to open link to " + address + " - retrying.");
                try
                {
                    Thread.sleep(5000);   // TODO: configure?
                }
                catch (InterruptedException ex)
                {
                    Thread.currentThread().interrupt();
                }
            }
        }

        return new MessageReply(MessageReply.Type.ERROR, new ErrorMessage("Link to node " + name +  " unavailable"));
    }

    private void open()
        throws IOException, ServiceConnectionException
    {
        this.connection = new Socket(address, portNo);

        cOut = connection.getOutputStream();
        cIn = connection.getInputStream();

        ASN1InputStream aIn = new ASN1InputStream(cIn, 300000); // TODO:

        nodeInfo = NodeInfo.getInstance(aIn.readObject());
        if (!name.equals(nodeInfo.getName()))
        {
            try
            {
                close();
            }
            catch (ServiceConnectionException e)
            {
                // ignore
            }
            eventNotifier.notify(EventNotifier.Level.ERROR, "Node " + name + " identified itself as " + nodeInfo.getName() + " - closing connection");
            throw new ServiceConnectionException("Node " + name + " identified itself as " + nodeInfo.getName() + " - closing connection");
        }
    }

    private void close()
        throws ServiceConnectionException
    {
        try
        {
            connection.close();
        }
        catch (Exception ex)
        {
            throw new ServiceConnectionException(ex.getMessage(), ex);
        }
        finally
        {
            connection = null;
            listener.status(name, false);
        }
    }

    private void buildConnection()
        throws ServiceConnectionException
    {
        for (int counter = 0; counter < 6; counter++)
        {
            try
            {
                this.open();

                listener.status(name, true);

                return;
            }
            catch (Exception e)
            {
                eventNotifier.notify(EventNotifier.Level.WARN, "Unable to open link to " + address + ":" + portNo + " - retrying.");
                try
                {
                    Thread.sleep(5000);   // TODO: configure?
                }
                catch (InterruptedException ex)
                {
                    Thread.currentThread().interrupt();
                }
            }
        }

        isTryingToConnect.set(true);

        eventNotifier.notify(EventNotifier.Level.WARN, "Node marked as unavailable " + address + ":" + portNo);

        listener.status(name, false);

         // TODO: use some sort of scheduler
        new Thread(new OpenTask()).start();

        throw new ServiceConnectionException("Node unavailable " + address + ":" + portNo);
    }

    private class OpenTask
        implements Runnable
    {
        @Override
        public void run()
        {
            while (!isShutdown.get())
            {
                try
                {
                    NodeServicesConnection.this.open();

                    isTryingToConnect.set(false);

                    listener.status(name, true);

                    return;
                }
                catch (Exception e)
                {
                    eventNotifier.notify(EventNotifier.Level.WARN, "Unable to open link to " + address + ":" + portNo + " - retrying.");
                    try
                    {
                        Thread.sleep(10000);   // TODO: configure?
                    }
                    catch (InterruptedException ex)
                    {
                        Thread.currentThread().interrupt();
                    }
                }
            }
        }
    }
}
