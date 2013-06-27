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

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashSet;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.cryptoworkshop.ximix.common.message.ClientMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.FetchPublicKeyMessage;
import org.cryptoworkshop.ximix.common.message.GenerateKeyPairMessage;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.service.AdminServicesConnection;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;

public class ClientKeyGenerationService
    implements KeyGenerationService
{
    private AdminServicesConnection connection;

    public ClientKeyGenerationService(AdminServicesConnection connection)
    {
        this.connection = connection;
    }

    @Override
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

    @Override
    public byte[] generatePublicKey(String keyID, int thresholdNumber, String... nodeNames)
        throws ServiceConnectionException
    {
        // TODO: need to generate h from appropriate EC domain parameters
        BigInteger h = BigInteger.valueOf(1000);
        MessageReply reply = connection.sendMessage(CommandMessage.Type.INITIATE_GENERATE_KEY_PAIR, new GenerateKeyPairMessage(keyID, thresholdNumber, h, new HashSet(Arrays.asList(nodeNames))));

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
            e.printStackTrace();
            throw new ServiceConnectionException("Malformed public key response.");
        }
    }
}
