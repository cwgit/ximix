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
import java.net.Socket;

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

    private NodeInfo nodeInfo;
    private Socket connection;
    private InputStream cIn;
    private OutputStream cOut;

    public NodeServicesConnection(NodeConfig config, EventNotifier eventNotifier)
        throws IOException
    {
        this.eventNotifier = eventNotifier;
        this.connection = new Socket(config.getAddress(), config.getPortNo());

        cOut = connection.getOutputStream();
        cIn = connection.getInputStream();

        ASN1InputStream aIn = new ASN1InputStream(cIn, 300000); // TODO:
        synchronized (this)
        {
            nodeInfo = NodeInfo.getInstance(aIn.readObject());
        }
    }

    @Override
    public void close()
        throws ServiceConnectionException
    {
        synchronized (this)
        {
            try
            {
                connection.close();
            }
            catch (Exception ex)
            {
                throw new ServiceConnectionException(ex.getMessage());
            }
        }
    }

    public String getName()
    {
        return nodeInfo.getName();
    }

    public CapabilityMessage[] getCapabilities()
    {
        return nodeInfo.getCapabilities();
    }

    @Override
    public EventNotifier getEventNotifier()
    {
        return eventNotifier;
    }

    public MessageReply sendMessage(MessageType type, ASN1Encodable messagePayload)
        throws ServiceConnectionException
    {
        try
        {
            synchronized (this)
            {
                if (type instanceof ClientMessage.Type)
                {
                    cOut.write(new ClientMessage((ClientMessage.Type)type, messagePayload).getEncoded());
                }
                else
                {
                    cOut.write(new CommandMessage((CommandMessage.Type)type, messagePayload).getEncoded());
                }
                return MessageReply.getInstance(new ASN1InputStream(cIn, 300000).readObject());      // TODO
            }
        }
        catch (Exception e)
        {
            eventNotifier.notify(EventNotifier.Level.ERROR, "couldn't send: " + e.getMessage(), e);

            return new MessageReply(MessageReply.Type.ERROR, new ErrorMessage("couldn't send: " + e.getMessage()));
        }
    }
}
