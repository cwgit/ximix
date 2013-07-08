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

import org.bouncycastle.asn1.ASN1String;
import org.cryptoworkshop.ximix.common.message.*;
import org.cryptoworkshop.ximix.common.service.AdminServicesConnection;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.crypto.KeyGenerationOptions;

import java.io.IOException;
import java.math.BigInteger;

public class KeyGenerationCommandService
    implements KeyGenerationService
{
    private AdminServicesConnection connection;

    public KeyGenerationCommandService(AdminServicesConnection connection)
    {
        this.connection = connection;
    }

    @Override
    public void shutdown()
        throws ServiceConnectionException
    {
        connection.close();
    }

    @Override
    public byte[] generatePublicKey(String keyID, KeyGenerationOptions keyGenOptions)
        throws ServiceConnectionException
    {
        BigInteger h = BigInteger.valueOf(1000001); // TODO
        final GenerateKeyPairMessage genKeyPairMessage = new GenerateKeyPairMessage(keyID, new ECKeyGenParams(h, keyGenOptions.getParameters()[0]), keyGenOptions.getThreshold(), keyGenOptions.getNodesToUse());

        MessageReply reply = connection.sendMessage(keyGenOptions.getNodesToUse()[0], CommandMessage.Type.INITIATE_GENERATE_KEY_PAIR, genKeyPairMessage);

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
        final FetchPublicKeyMessage genKeyPairMessage = new FetchPublicKeyMessage(keyID);

        MessageReply reply = connection.sendMessage(ClientMessage.Type.FETCH_PUBLIC_KEY, genKeyPairMessage);

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
