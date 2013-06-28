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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.message.ClientMessage;
import org.cryptoworkshop.ximix.common.message.ECDSACreateMessage;
import org.cryptoworkshop.ximix.common.message.ECDSAResponseMessage;
import org.cryptoworkshop.ximix.common.message.FetchPublicKeyMessage;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.service.ClientServiceConnectionException;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;
import org.cryptoworkshop.ximix.crypto.threshold.LagrangeWeightCalculator;

public class ClientSigningService
    implements SigningService
{
    private ServicesConnection connection;

    public ClientSigningService(ServicesConnection connection)
    {
        this.connection = connection;
    }

    public byte[] generateSignature(String keyID, byte[] message)
        throws ServiceConnectionException
    {
        MessageReply keyReply = connection.sendMessage(ClientMessage.Type.FETCH_PUBLIC_KEY, new FetchPublicKeyMessage(keyID));

        try
        {
            SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfo.getInstance(keyReply.getPayload());
            ECDomainParameters domainParams = ((ECPublicKeyParameters)PublicKeyFactory.createKey(pubKeyInfo)).getParameters();

            BigInteger n = domainParams.getN();
            BigInteger e = calculateE(n, message);
            BigInteger r = null;
            BigInteger s = null;

            // 5.3.2
            do // generate s
            {
                BigInteger k = null;
                int nBitLength = n.bitLength();

                do // generate r
                {
                    do
                    {
                        k = new BigInteger(nBitLength, new SecureRandom());
                    }
                    while (k.equals(BigInteger.ZERO) || k.compareTo(n) >= 0);

                    ECPoint p = domainParams.getG().multiply(k);

                    // 5.3.3
                    BigInteger x = p.getX().toBigInteger();

                    r = x.mod(n);
                }
                while (r.equals(BigInteger.ZERO));

                MessageReply sigReply = connection.sendMessage(ClientMessage.Type.CREATE_SIGNATURE, new ECDSACreateMessage(keyID, r));

                ASN1Sequence seq = ASN1Sequence.getInstance(sigReply.getPayload());
                BigInteger[] dMultrVals = new BigInteger[seq.size()];

                for (int i = 0; i != seq.size(); i++)
                {
                    dMultrVals[i] = ECDSAResponseMessage.getInstance(seq.getObjectAt(i)).getValue();
                }

                LagrangeWeightCalculator calculator = new LagrangeWeightCalculator(dMultrVals.length, domainParams.getN());

                BigInteger[] weights = calculator.computeWeights(dMultrVals);

                // weighting
                BigInteger dMultr = dMultrVals[0].multiply(weights[0]);
                for (int i = 1; i < weights.length; i++)
                {
                    if (dMultrVals[i] != null)
                    {
                        dMultr = dMultr.add(dMultrVals[i].multiply(weights[i]));
                    }
                }

                s = k.modInverse(n).multiply(e.add(dMultr)).mod(n);
            }
            while (s.equals(BigInteger.ZERO));

            ASN1EncodableVector v = new ASN1EncodableVector();

            v.add(new ASN1Integer(r));
            v.add(new ASN1Integer(s));

            return new DERSequence(v).getEncoded();
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

    private BigInteger calculateE(BigInteger n, byte[] message)
    {
        int log2n = n.bitLength();
        int messageBitLength = message.length * 8;

        if (log2n >= messageBitLength)
        {
            return new BigInteger(1, message);
        }
        else
        {
            BigInteger trunc = new BigInteger(1, message);

            trunc = trunc.shiftRight(messageBitLength - log2n);

            return trunc;
        }
    }
}
