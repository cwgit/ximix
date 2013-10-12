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
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.MessageType;

/**
 * Internal implementation of a general ServicesConnection. Unlike a NodeServicesConnection this class addresses the
 * Ximix network as a whole and will choose the first available suitable node for processing a message.
 */
class ServicesConnectionImpl
    implements ServicesConnection
{
    private NodeServicesConnection connection;
    private NodeConfig nodeConf;

    public ServicesConnectionImpl(List<NodeConfig> configList)
    {
        //
        // find a node to connect to
        //
        // TODO: this should start at a random point in the list

        int start = 0;
        for (int i = 0; i != configList.size(); i++)
        {
            int nodeNo = (start + i) % configList.size();

            nodeConf = configList.get(nodeNo);

            if (nodeConf.getThrowable() == null)
            {
                try
                {
                    if (getConnection() == null)
                    {
                        continue;
                    }
                }
                catch (IOException e)
                {
                    continue;
                }
                break;
            }
        }
    }

    @Override
    public void close()
        throws ServiceConnectionException
    {
        connection.close();
    }

    private synchronized NodeServicesConnection resetConnection()
    {
        // TODO: need to look into possible connection leakage here. 2 threads may end up trying to reset at the same time.
        connection = null;

        try
        {
            return getConnection();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    private synchronized NodeServicesConnection getConnection()
        throws IOException
    {
        if (connection == null)
        {
            connection = new NodeServicesConnection(nodeConf);
        }

        return connection;
    }

    public CapabilityMessage[] getCapabilities()
    {
        try
        {
            return getConnection().getCapabilities();
        }
        catch (IOException e)
        {
            return new CapabilityMessage[0];
        }
    }

    public MessageReply sendMessage(MessageType type, ASN1Encodable messagePayload)
        throws ServiceConnectionException
    {
        try
        {
            return getConnection().sendMessage(type, messagePayload);
        }
        catch (Exception e)
        {
            return resetConnection().sendMessage(type, messagePayload);
        }
    }
}
