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

import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01Parameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.cryptoworkshop.ximix.client.connection.AdminServicesConnection;
import org.cryptoworkshop.ximix.client.connection.ServiceConnectionException;
import org.cryptoworkshop.ximix.client.connection.signing.message.BLSPartialCreateMessage;
import org.cryptoworkshop.ximix.common.asn1.message.BigIntegerMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ClientMessage;
import org.cryptoworkshop.ximix.common.asn1.message.ElementMessage;
import org.cryptoworkshop.ximix.common.asn1.message.FetchPublicKeyMessage;
import org.cryptoworkshop.ximix.common.asn1.message.KeyIDMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.MessageType;
import org.cryptoworkshop.ximix.common.asn1.message.SignatureCreateMessage;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.common.crypto.BLSPublicKeyFactory;
import org.cryptoworkshop.ximix.common.crypto.threshold.LagrangeWeightCalculator;

/**
 * Client side signing service for accumulating a BLS signature.
 */
public class BLSSigningService
    extends BaseSigningService
{
    public BLSSigningService(AdminServicesConnection connection)
    {
        super(Algorithm.BLS, connection);
    }

    public static enum Type
        implements MessageType
    {
        FETCH_SEQUENCE_NO,
        PRIVATE_KEY_SIGN
    }

    public MessageReply generateSig(SignatureCreateMessage blsCreate)
        throws ServiceConnectionException, IOException
    {
        Participant[] participants = new Participant[blsCreate.getNodesToUse().size()];
        int index = 0;

        for (String name : blsCreate.getNodesToUse())
        {
            MessageReply seqRep = sendMessage(name, Type.FETCH_SEQUENCE_NO, new KeyIDMessage(blsCreate.getKeyID()));
            // TODO: need to drop out people who don't reply.
            participants[index] = new Participant(BigIntegerMessage.getInstance(seqRep.getPayload()).getValue().intValue(), name);
            index++;
        }

        FetchPublicKeyMessage fetchMessage = new FetchPublicKeyMessage(blsCreate.getKeyID());

        MessageReply reply = connection.sendMessage(ClientMessage.Type.FETCH_PUBLIC_KEY, fetchMessage);

        SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfo.getInstance(reply.getPayload());
        BLS01Parameters domainParams = BLSPublicKeyFactory.createKey(pubKeyInfo).getParameters();
        Pairing pairing = PairingFactory.getPairing(domainParams.getCurveParameters());

        byte[] hash = blsCreate.getMessage();
        Element h = pairing.getG1().newElement().setFromHash(hash, 0, hash.length);

        // TODO: need to take into account node failure during startup.
        Element signature = accumulateElement(participants, Type.PRIVATE_KEY_SIGN, new BLSPartialCreateMessage(blsCreate.getKeyID(), h, participants), pairing, pairing.getZr().getOrder());

        signature = signature.powZn(pairing.getZr().newOneElement());

        return new MessageReply(MessageReply.Type.OKAY, new DEROctetString(signature.toBytes()));
    }

    protected Element accumulateElement(Participant[] nodes, Enum fetchOperatorType, ASN1Encodable request, Pairing pairing, BigInteger fieldSize)
        throws ServiceConnectionException
    {
        ASN1Encodable[] valueShares = getShareData(nodes, fetchOperatorType, request);

        //
        // we don't need to know how many peers, just the maximum index (max(sequenceNo) + 1) of the one available
        //
        LagrangeWeightCalculator calculator = new LagrangeWeightCalculator(valueShares.length, fieldSize);

        BigInteger[] weights = calculator.computeWeights(valueShares);

        int baseIndex = getBaseIndex(valueShares);

        Element        baseValue = ElementMessage.getInstance(pairing, valueShares[baseIndex]).getValue();
        BigInteger     baseWeight = weights[baseIndex];

        // weighting
        Element value = baseValue.powZn(pairing.getZr().newElement(baseWeight));
        for (int i = baseIndex + 1; i < weights.length; i++)
        {
            if (valueShares[i] != null)
            {
                value = value.mul(ElementMessage.getInstance(pairing, valueShares[i]).getValue().powZn(pairing.getZr().newElement(weights[i])));
            }
        }

        return value;
    }
}
