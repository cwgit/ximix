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

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.cryptoworkshop.ximix.client.connection.AdminServicesConnection;
import org.cryptoworkshop.ximix.client.connection.ServiceConnectionException;
import org.cryptoworkshop.ximix.client.connection.signing.message.ECDSAInitialiseMessage;
import org.cryptoworkshop.ximix.client.connection.signing.message.ECDSAPartialCreateMessage;
import org.cryptoworkshop.ximix.common.asn1.message.BigIntegerMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ClientMessage;
import org.cryptoworkshop.ximix.common.asn1.message.FetchPublicKeyMessage;
import org.cryptoworkshop.ximix.common.asn1.message.IDMessage;
import org.cryptoworkshop.ximix.common.asn1.message.KeyIDMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.MessageType;
import org.cryptoworkshop.ximix.common.asn1.message.SignatureCreateMessage;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.common.crypto.threshold.LagrangeWeightCalculator;
import org.cryptoworkshop.ximix.common.util.EventNotifier;

/**
 * Client side signing service for accumulating an ECDSA signature.
 */
public class ECDSASigningService
    extends BaseSigningService
{
    public static enum Type
        implements MessageType
    {
        INIT_K_AND_P,
        INIT_A,
        INIT_B,
        INIT_C,
        INIT_R,
        INIT_MU,
        FETCH_P,
        FETCH_MU,
        FETCH_SEQUENCE_NO,
        FETCH_SIG_ID,
        FETCH_R,
        PRIVATE_KEY_SIGN,
        STORE_K,
        STORE_A,
        STORE_B,
        STORE_C,
        STORE_P
    }

    public ECDSASigningService(AdminServicesConnection connection)
    {
        super(Algorithm.ECDSA, connection);
    }

    public MessageReply generateSig(SignatureCreateMessage ecdsaCreate)
        throws ServiceConnectionException, IOException
    {
        Participant[] participants = new Participant[ecdsaCreate.getNodesToUse().size()];
        int index = 0;

        for (String name : ecdsaCreate.getNodesToUse())
        {
            MessageReply seqRep = sendMessage(name, Type.FETCH_SEQUENCE_NO, new KeyIDMessage(ecdsaCreate.getKeyID()));
            // TODO: need to drop out people who don't reply.
            participants[index] = new Participant(BigIntegerMessage.getInstance(seqRep.getPayload()).getValue().intValue(), name);
            index++;
        }

        FetchPublicKeyMessage fetchMessage = new FetchPublicKeyMessage(ecdsaCreate.getKeyID());

        MessageReply reply = connection.sendMessage(ClientMessage.Type.FETCH_PUBLIC_KEY, fetchMessage);

        ECDomainParameters domainParams = ((ECPublicKeyParameters)PublicKeyFactory.createKey(SubjectPublicKeyInfo.getInstance(reply.getPayload()))).getParameters();
        BigInteger n = domainParams.getN();
        BigInteger e = calculateE(n, ecdsaCreate.getMessage());
        // TODO: need to take into account node failure during startup.

        reply = sendMessage(participants[0].getName(), Type.FETCH_SIG_ID, DERNull.INSTANCE);

        SigID sigID = new SigID(IDMessage.getInstance(reply.getPayload()).getID());

        BigInteger r, s;
        do // generate s
        {
            ECDSAInitialiseMessage initialiseMessage = new ECDSAInitialiseMessage(sigID.getID(), ecdsaCreate.getKeyID(), ecdsaCreate.getThreshold(), domainParams.getN(), participants);

            sendInitialiseMessage(Type.INIT_K_AND_P, initialiseMessage);
            sendInitialiseMessage(Type.INIT_A, initialiseMessage);
            sendInitialiseMessage(Type.INIT_B, initialiseMessage);
            sendInitialiseMessage(Type.INIT_C, initialiseMessage);
            sendInitialiseMessage(Type.INIT_R, initialiseMessage);
            sendInitialiseMessage(Type.INIT_MU, initialiseMessage);

            MessageReply seqRep = sendMessage(participants[0].getName(), Type.FETCH_R, new IDMessage(sigID.getID()));

            r = BigIntegerMessage.getInstance(seqRep.getPayload()).getValue();

            s = accumulateBigInteger(participants, Type.PRIVATE_KEY_SIGN, new ECDSAPartialCreateMessage(sigID.getID(), ecdsaCreate.getKeyID(), e, participants), n);
        }
        while (s.equals(BigInteger.ZERO));

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));

        return new MessageReply(MessageReply.Type.OKAY, new DERSequence(v));
    }

    private void sendInitialiseMessage(Type initType, ECDSAInitialiseMessage createMessage)
    {
        Participant[] nodes = createMessage.getNodesToUse();

        for (Participant nodeName : nodes)
        {
            try
            {
                sendMessage(nodeName.getName(), initType, createMessage);
            }
            catch (ServiceConnectionException e)
            {
                connection.getEventNotifier().notify(EventNotifier.Level.ERROR, "sendInitialiseMessage failure: " + e.getMessage(), e);
            }
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

    protected BigInteger accumulateBigInteger(Participant[] nodes, Enum fetchOperatorType, ASN1Encodable request, BigInteger fieldSize)
        throws ServiceConnectionException
    {
        ASN1Encodable[] valueShares = getShareData(nodes, fetchOperatorType, request);

        //
        // we don't need to know how many peers, just the maximum index (max(sequenceNo) + 1) of the one available
        //
        LagrangeWeightCalculator calculator = new LagrangeWeightCalculator(valueShares.length, fieldSize);

        BigInteger[] weights = calculator.computeWeights(valueShares);

        int baseIndex = getBaseIndex(valueShares);

        BigInteger     baseValue = BigIntegerMessage.getInstance(valueShares[baseIndex]).getValue();
        BigInteger     baseWeight = weights[baseIndex];

        // weighting
        BigInteger value = baseValue.multiply(baseWeight);
        for (int i = baseIndex + 1; i < weights.length; i++)
        {
            if (valueShares[i] != null)
            {
                value = value.add(BigIntegerMessage.getInstance(valueShares[i]).getValue().multiply(weights[i])).mod(fieldSize);
            }
        }

        return value;
    }
}
