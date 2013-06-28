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
package org.cryptoworkshop.ximix.crypto.service;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.message.Capability;
import org.cryptoworkshop.ximix.common.message.ClientMessage;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.CreateSignatureMessage;
import org.cryptoworkshop.ximix.common.message.ECDSACreateMessage;
import org.cryptoworkshop.ximix.common.message.ECDSAPartialCreateMessage;
import org.cryptoworkshop.ximix.common.message.ECDSAResponseMessage;
import org.cryptoworkshop.ximix.common.message.FetchPublicKeyMessage;
import org.cryptoworkshop.ximix.common.message.Message;
import org.cryptoworkshop.ximix.common.message.MessageBlock;
import org.cryptoworkshop.ximix.common.message.MessageReply;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.service.Service;
import org.cryptoworkshop.ximix.common.service.ServicesConnection;
import org.cryptoworkshop.ximix.crypto.threshold.LagrangeWeightCalculator;

public class NodeSigningService
    implements Service
{
    private final NodeContext nodeContext;

    public NodeSigningService(NodeContext nodeContext, Config config)
    {
        this.nodeContext = nodeContext;
    }

    public byte[] generateSignature(String keyID, byte[] hash)
    {
        // TODO: needs to be distributed
        ECDSASigner signer = new ECDSASigner();

        try
        {
            CipherParameters privKey = null; // nodeContext.performPartialSign(keyID);

            signer.init(true, privKey);

            BigInteger[] rs = signer.generateSignature(hash);

            ASN1EncodableVector v = new ASN1EncodableVector();

             v.add(new ASN1Integer(rs[0]));
             v.add(new ASN1Integer(rs[1]));

            return new DERSequence(v).getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            // TODO: some sort of sig failure exception will be required here...
        }

        return null;
    }

    public Capability getCapability()
    {
        return new Capability(Capability.Type.SIGNING, new ASN1Encodable[0]); // TODO:
    }

    public MessageReply handle(Message message)
    {
        try
        {
            if (message.getType() instanceof ClientMessage.Type)
            {
                switch (((ClientMessage)message).getType())
                {
                case CREATE_SIGNATURE:
                    ECDSACreateMessage ecdsaCreate = ECDSACreateMessage.getInstance(message.getPayload());
                    SubjectPublicKeyInfo pubKeyInfo =  nodeContext.getPublicKey(ecdsaCreate.getKeyID());
                    ECDomainParameters domainParams = ((ECPublicKeyParameters)PublicKeyFactory.createKey(pubKeyInfo)).getParameters();

                    BigInteger n = domainParams.getN();
                    BigInteger e = calculateE(n, ecdsaCreate.getMessage());
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

                        Map<String, ServicesConnection> nodes = nodeContext.getPeerMap();
                        MessageReply[] replys = new MessageReply[nodes.size()];
                        // TODO: order needs to enforced.

                        BigInteger val = nodeContext.performPartialSign(ecdsaCreate.getKeyID(), r);

                        int counter = 0;
                        for (String nodeName : nodes.keySet())
                        {
                            replys[counter++] = nodes.get(nodeName).sendMessage(CommandMessage.Type.PARTIAL_ECDSA_SIGN, new ECDSAPartialCreateMessage(ecdsaCreate.getKeyID(), r));
                        }

                        BigInteger[] dMultrVals = new BigInteger[1 + nodes.keySet().size()];

                        ASN1EncodableVector v = new ASN1EncodableVector();

                        dMultrVals[0] = val;

                        for (int i = 0; i != replys.length; i++)
                        {
                            if (replys[i] == null || replys[i].getType() != MessageReply.Type.OKAY)
                            {
                                dMultrVals[i + 1] = null;
                            }
                            else
                            {
                                dMultrVals[i + 1] = ECDSAResponseMessage.getInstance(replys[i].getPayload()).getValue();
                            }
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

                    return new MessageReply(MessageReply.Type.OKAY, new DERSequence(v));
                default:
                    return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Unknown command in NodeSigningService."));
                }
            }
            else
            {
                switch (((CommandMessage)message).getType())
                {
                case PARTIAL_ECDSA_SIGN:
                    ECDSAPartialCreateMessage partialMessage = ECDSAPartialCreateMessage.getInstance(message.getPayload());

                    BigInteger val = nodeContext.performPartialSign(partialMessage.getKeyID(), partialMessage.getR());

                    return new MessageReply(MessageReply.Type.OKAY, new ECDSAResponseMessage(val));
                default:
                    return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("Unknown command in NodeSigningService."));
                }
            }
        }
        catch (Exception e)
        {
            return new MessageReply(MessageReply.Type.ERROR, new DERUTF8String("NodeKeyGenerationService failure: " + e.getMessage()));
        }
    }

    public boolean isAbleToHandle(Enum type)
    {
        return type == ClientMessage.Type.CREATE_SIGNATURE || type == CommandMessage.Type.PARTIAL_ECDSA_SIGN;
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
