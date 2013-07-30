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
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.math.ec.ECConstants;
import org.cryptoworkshop.ximix.common.message.AlgorithmServiceMessage;
import org.cryptoworkshop.ximix.common.message.ClientMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.FetchPublicKeyMessage;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.service.AdminServicesConnection;
import org.cryptoworkshop.ximix.common.service.Algorithm;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.crypto.KeyGenerationOptions;
import org.cryptoworkshop.ximix.crypto.key.BLSKeyPairGenerator;
import org.cryptoworkshop.ximix.crypto.key.ECKeyPairGenerator;
import org.cryptoworkshop.ximix.crypto.key.message.KeyGenParams;
import org.cryptoworkshop.ximix.crypto.key.message.KeyGenerationMessage;
import org.cryptoworkshop.ximix.crypto.key.message.KeyPairGenerateMessage;

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
            reply = connection.sendMessage(keyGenOptions.getNodesToUse()[0], CommandMessage.Type.GENERATE_KEY_PAIR, new AlgorithmServiceMessage(keyGenOptions.getAlgorithm(), new KeyPairGenerateMessage(keyGenOptions.getAlgorithm(), BLSKeyPairGenerator.Type.INITIATE, genKeyPairMessage)));
        }
        else
        {
            reply = connection.sendMessage(keyGenOptions.getNodesToUse()[0], CommandMessage.Type.GENERATE_KEY_PAIR, new AlgorithmServiceMessage(keyGenOptions.getAlgorithm(), new KeyPairGenerateMessage(keyGenOptions.getAlgorithm(), ECKeyPairGenerator.Type.INITIATE, genKeyPairMessage)));
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

    static BigInteger generateK(BigInteger n, SecureRandom random)
    {
        int                    nBitLength = n.bitLength();
        BigInteger             k = new BigInteger(nBitLength, random);

        while (k.equals(ECConstants.ZERO) || (k.compareTo(n) >= 0))
        {
            k = new BigInteger(nBitLength, random);
        }

        return k;
    }
}
