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
package org.cryptoworkshop.ximix.crypto.client;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.cryptoworkshop.ximix.common.message.CreateSignatureMessage;
import org.cryptoworkshop.ximix.common.message.FetchPublicKeyMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;

public class ClientSigningService
    implements SigningService
{
    private ServicesConnection connection;

    public ClientSigningService(ServicesConnection connection)
    {
        this.connection = connection;
    }

    public byte[] generateSignature(String keyID, byte[] hash)
        throws ServiceConnectionException
    {
        MessageReply reply = connection.sendThresholdMessage(Message.Type.CREATE_SIGNATURE, new CreateSignatureMessage(keyID, hash));

        if (reply.getType() != MessageReply.Type.OKAY)
        {
            throw new ServiceConnectionException("message failed");
        }

        return ASN1OctetString.getInstance(reply.getPayload().toASN1Primitive()).getOctets();
    }

    public byte[] fetchPublicKey(String keyID)
        throws ServiceConnectionException
    {
        MessageReply reply = connection.sendMessage(Message.Type.FETCH_PUBLIC_KEY, new FetchPublicKeyMessage(keyID));

        if (reply.getType() != MessageReply.Type.OKAY)
        {
            throw new ServiceConnectionException("message failed");
        }

        try
        {
            return SubjectPublicKeyInfo.getInstance(reply.getPayload().toASN1Primitive()).getEncoded();
        }
        catch (Exception e)
        {                                 e.printStackTrace();
            throw new ServiceConnectionException("Malformed public key response.");
        }
    }
}
