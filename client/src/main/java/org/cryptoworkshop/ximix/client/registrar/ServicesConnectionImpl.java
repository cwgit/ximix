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
package org.cryptoworkshop.ximix.client.registrar;

import java.io.IOException;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.MessageType;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;

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
                if (getConnection() == null)
                {
                    continue;
                }
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

        return getConnection();
    }

    private synchronized NodeServicesConnection getConnection()
    {
        if (connection == null)
        {
            try
            {
                connection = new NodeServicesConnection(nodeConf);
            }
            catch (IOException e)
            {
                //   System.out.print(e.getMessage());
                // TODO:
            }
        }

        return connection;
    }

    public CapabilityMessage[] getCapabilities()
    {
        return getConnection().getCapabilities();
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
