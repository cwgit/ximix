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

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.cryptoworkshop.ximix.client.SignatureGenerationOptions;
import org.cryptoworkshop.ximix.client.SigningService;
import org.cryptoworkshop.ximix.common.asn1.message.AlgorithmServiceMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ClientMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.FetchPublicKeyMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.MessageType;
import org.cryptoworkshop.ximix.common.asn1.message.SignatureCreateMessage;
import org.cryptoworkshop.ximix.common.asn1.message.SignatureMessage;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;

/**
 * Internal implementation of the SigningService interface. This class creates the messages which are then sent down
 * the ServicesConnection.
 */
class ClientSigningService
    implements SigningService
{
    private enum Type
        implements MessageType
    {
        GENERATE
    }

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
            MessageReply reply;

            if (sigGenOptions.getAlgorithm() == Algorithm.ECDSA)
            {
                reply = connection.sendMessage(CommandMessage.Type.SIGNATURE_MESSAGE, new AlgorithmServiceMessage(sigGenOptions.getAlgorithm(), new SignatureMessage(Algorithm.ECDSA, Type.GENERATE, new SignatureCreateMessage(keyID, message, sigGenOptions.getThreshold(), sigGenOptions.getNodesToUse()))));
            }
            else
            {
                reply = connection.sendMessage(CommandMessage.Type.SIGNATURE_MESSAGE, new AlgorithmServiceMessage(sigGenOptions.getAlgorithm(), new SignatureMessage(Algorithm.BLS, Type.GENERATE, new SignatureCreateMessage(keyID, message, sigGenOptions.getThreshold(), sigGenOptions.getNodesToUse()))));
            }

            if (reply.getType() == MessageReply.Type.OKAY)
            {
                if (sigGenOptions.getAlgorithm() == Algorithm.ECDSA)
                {
                    return reply.getPayload().toASN1Primitive().getEncoded();
                }
                else
                {
                    return ASN1OctetString.getInstance(reply.getPayload().toASN1Primitive()).getOctets();
                }
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
        {
            throw new ServiceConnectionException("Malformed public key response.");
        }
    }
}
