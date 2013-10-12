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

import org.bouncycastle.asn1.ASN1String;
import org.cryptoworkshop.ximix.client.KeyGenerationOptions;
import org.cryptoworkshop.ximix.client.KeyGenerationService;
import org.cryptoworkshop.ximix.common.asn1.message.AlgorithmServiceMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ClientMessage;
import org.cryptoworkshop.ximix.common.asn1.message.CommandMessage;
import org.cryptoworkshop.ximix.common.asn1.message.FetchPublicKeyMessage;
import org.cryptoworkshop.ximix.common.asn1.message.KeyGenParams;
import org.cryptoworkshop.ximix.common.asn1.message.KeyGenerationMessage;
import org.cryptoworkshop.ximix.common.asn1.message.KeyPairGenerateMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.MessageType;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;

/**
 * Internal implementation of the KeyGenerationService interface. This class creates the messages which are then sent down
 * the ServicesConnection.
 */
class KeyGenerationCommandService
    implements KeyGenerationService
{
    private enum Type
        implements MessageType
    {
        INITIATE
    }

    private AdminServicesConnection connection;

    public KeyGenerationCommandService(AdminServicesConnection connection)
    {
        this.connection = connection;
    }

    @Override
    public void shutdown()
        throws ServiceConnectionException
    {
        // nothing to do here
    }

    @Override
    public byte[] generatePublicKey(String keyID, KeyGenerationOptions keyGenOptions)
        throws ServiceConnectionException
    {
        final KeyGenerationMessage genKeyPairMessage = new KeyGenerationMessage(keyGenOptions.getAlgorithm(), keyID, new KeyGenParams(keyGenOptions.getParameters()[0]), keyGenOptions.getThreshold(), keyGenOptions.getNodesToUse());

        MessageReply reply;

        if (keyGenOptions.getAlgorithm() == Algorithm.BLS)
        {
            reply = connection.sendMessage(keyGenOptions.getNodesToUse()[0], CommandMessage.Type.GENERATE_KEY_PAIR, new AlgorithmServiceMessage(keyGenOptions.getAlgorithm(), new KeyPairGenerateMessage(keyGenOptions.getAlgorithm(), Type.INITIATE, genKeyPairMessage)));
        }
        else
        {
            reply = connection.sendMessage(keyGenOptions.getNodesToUse()[0], CommandMessage.Type.GENERATE_KEY_PAIR, new AlgorithmServiceMessage(keyGenOptions.getAlgorithm(), new KeyPairGenerateMessage(keyGenOptions.getAlgorithm(), Type.INITIATE, genKeyPairMessage)));
        }

        if (reply.getType() != MessageReply.Type.OKAY)
        {
            if (reply.getPayload() instanceof ASN1String)
            {
                throw new ServiceConnectionException(((ASN1String)reply.getPayload()).getString());
            }
            else
            {
                throw new ServiceConnectionException("Unknown connection failure.");
            }
        }

        try
        {
            return reply.getPayload().toASN1Primitive().getEncoded();
        }
        catch (IOException e)
        {
            throw new ServiceConnectionException("Malformed public key returned: " + e.getMessage());
        }
    }

    @Override
    public byte[] fetchPublicKey(String keyID)
        throws ServiceConnectionException
    {
        FetchPublicKeyMessage fetchMessage = new FetchPublicKeyMessage(keyID);

        MessageReply reply = connection.sendMessage(ClientMessage.Type.FETCH_PUBLIC_KEY, fetchMessage);

        try
        {
            if (reply.getPayload() != null)
            {
                return reply.getPayload().toASN1Primitive().getEncoded();
            }

            return null;
        }
        catch (IOException e)
        {
            throw new ServiceConnectionException("malformed public key returned: " + e.getMessage());
        }
    }
}
