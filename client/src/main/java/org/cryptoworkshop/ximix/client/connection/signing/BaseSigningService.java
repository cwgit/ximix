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
package org.cryptoworkshop.ximix.client.connection.signing;

import org.bouncycastle.asn1.ASN1Encodable;
import org.cryptoworkshop.ximix.client.connection.AdminServicesConnection;
import org.cryptoworkshop.ximix.client.connection.ServiceConnectionException;
import org.cryptoworkshop.ximix.common.asn1.message.AlgorithmServiceMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.ShareMessage;
import org.cryptoworkshop.ximix.common.asn1.message.SignatureMessage;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;

/**
 * Base class for a client side signing service.
 */
public abstract class BaseSigningService
{
    private final Algorithm algorithm;
    protected final AdminServicesConnection connection;

    protected BaseSigningService(Algorithm algorithm, AdminServicesConnection connection)
    {
        this.algorithm = algorithm;
        this.connection = connection;
    }

    protected MessageReply sendMessage(String node, Enum type, ASN1Encodable message)
        throws ServiceConnectionException
    {
        return connection.sendMessage(node, CommandMessage.Type.SIGNATURE_MESSAGE, new AlgorithmServiceMessage(algorithm, new SignatureMessage(algorithm, type, message)));
    }

    /**
     * Find the first non-null element in a share array.
     *
     * @param valueShares  share array to examine
     * @return the index of the first non-null element.
     */
    protected int getBaseIndex(ASN1Encodable[] valueShares)
    {
        int  baseIndex = 0;
        for (int i = 0; i != valueShares.length; i++)
        {
            if (valueShares[i] != null)
            {
                baseIndex = i;
                break;
            }
        }
        return baseIndex;
    }

    /**
     * Return a properly distributed list of shares with null values occupying any gaps.
     *
     * @throws ServiceConnectionException
     */
    protected ASN1Encodable[] getShareData(Participant[] nodes, Enum fetchOperatorType, ASN1Encodable request)
        throws ServiceConnectionException
    {
        MessageReply[] replys = new MessageReply[nodes.length];

        // TODO: deal with drop outs
        int count = 0;
        while (count != nodes.length)
        {
            replys[count] = sendMessage(nodes[count].getName(), fetchOperatorType, request);
            if (replys[count].getType() != MessageReply.Type.OKAY)
            {
                                 // TODO: maybe log
                replys[count] = null;
            }
            count++;
        }

        ShareMessage[] shareMessages = new ShareMessage[nodes.length];
        int            maxSequenceNo = 0;

        for (int i = 0; i != shareMessages.length; i++)
        {
            shareMessages[i] = ShareMessage.getInstance(replys[i].getPayload());
            if (maxSequenceNo < shareMessages[i].getSequenceNo())
            {
                maxSequenceNo = shareMessages[i].getSequenceNo();
            }
        }

        ASN1Encodable[] valueShares = new ASN1Encodable[maxSequenceNo + 1];

        for (int i = 0; i != shareMessages.length; i++)
        {
            ShareMessage shareMsg = shareMessages[i];

            valueShares[shareMsg.getSequenceNo()] = shareMsg.getShareData();
        }

        return valueShares;
    }
}
