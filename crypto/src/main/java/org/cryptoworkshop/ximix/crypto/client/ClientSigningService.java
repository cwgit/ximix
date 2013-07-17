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

import java.io.IOException;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.cryptoworkshop.ximix.common.message.ClientMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.FetchPublicKeyMessage;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.message.SignatureMessage;
import org.cryptoworkshop.ximix.common.service.ClientServiceConnectionException;
import org.cryptoworkshop.ximix.common.service.KeyType;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;
import org.cryptoworkshop.ximix.crypto.SignatureGenerationOptions;
import org.cryptoworkshop.ximix.crypto.signature.ECDSASignerEngine;
import org.cryptoworkshop.ximix.crypto.signature.message.ECDSACreateMessage;

public class ClientSigningService
    implements SigningService
{
    private ServicesConnection connection;

    public ClientSigningService(ServicesConnection connection)
    {
        this.connection = connection;
    }

    @Override
    public void shutdown() throws ServiceConnectionException
    {
        connection.close();
    }

    public byte[] generateSignature(String keyID, SignatureGenerationOptions sigGenOptions, byte[] message)
        throws ServiceConnectionException
    {
        try
        {
            MessageReply reply = connection.sendMessage(CommandMessage.Type.SIGNATURE_MESSAGE, new SignatureMessage(KeyType.ECDSA, ECDSASignerEngine.Type.GENERATE, new ECDSACreateMessage(keyID, message, sigGenOptions.getThreshold(), sigGenOptions.getNodesToUse())));

            if (reply.getType() == MessageReply.Type.OKAY)
            {
                return reply.getPayload().toASN1Primitive().getEncoded();
            }

            throw new ClientServiceConnectionException("Unable to create signature");
        }
        catch (RuntimeException e)
        {
            throw new ClientServiceConnectionException("Unable to create signature: " + e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw new ClientServiceConnectionException("Unable to create signature: " + e.getMessage(), e);
        }
    }

    public byte[] fetchPublicKey(String keyID)
        throws ServiceConnectionException
    {
        MessageReply reply = connection.sendMessage(ClientMessage.Type.FETCH_PUBLIC_KEY, new FetchPublicKeyMessage(keyID));

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
