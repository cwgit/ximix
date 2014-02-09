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
package org.cryptoworkshop.ximix.common.asn1.message;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.asn1.board.PointSequence;

/**
 * Class used to define the fields in a decryption challenge log message.
 */
public class ChallengeLogMessage
    extends ASN1Object
{
    private final int index;
    private final int sequenceNo;
    private final boolean hasPassed;
    private final BigInteger m;
    private final SubjectPublicKeyInfo keyInfo;
    private final ECPoint[] sourceMessage;
    private final ECPoint[] challengeResult;

    /**
     * Base constructor.
     *
     * @param index the index number of the message challenged.
     * @param sequenceNo the sequenceNo in the sharing process for the node this message is based on.
     * @param hasPassed
     * @param m the multiplier "m" used in computing the challenge,
     * @param keyInfo the node's partial public key.
     * @param sourceMessage the input message for the challenge computation.
     * @param challengeResult the result of the challenge.
     */
    public ChallengeLogMessage(int index, int sequenceNo, boolean hasPassed, BigInteger m, SubjectPublicKeyInfo keyInfo, ECPoint[] sourceMessage, ECPoint[] challengeResult)
    {
        this.index = index;
        this.sequenceNo = sequenceNo;
        this.hasPassed = hasPassed;
        this.m = m;
        this.keyInfo = keyInfo;
        this.sourceMessage = sourceMessage;
        this.challengeResult = challengeResult;
    }

    private ChallengeLogMessage(ASN1Sequence seq)
    {
        this.index = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().intValue();
        this.sequenceNo = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue().intValue();
        this.hasPassed = ASN1Boolean.getInstance(seq.getObjectAt(2)).isTrue();
        this.m = ASN1Integer.getInstance(seq.getObjectAt(3)).getValue();
        this.keyInfo = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(4));

        ECPublicKeyParameters ecKey;
        try
        {
            ecKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("Unable to create EC key from keyInfo in sequence.");
        }

        this.sourceMessage = PointSequence.getInstance(ecKey.getParameters().getCurve(), ASN1Sequence.getInstance(seq.getObjectAt(5))).getECPoints();
        this.challengeResult = PointSequence.getInstance(ecKey.getParameters().getCurve(), ASN1Sequence.getInstance(seq.getObjectAt(6))).getECPoints();
    }

    /**
     * Create an instance of ChallengeLogMessage from the passed in object.
     *
     * @param o the source object to use.
     * @return a ChallengeLogMessage.
     */
    public static ChallengeLogMessage getInstance(Object o)
    {
        if (o instanceof ChallengeLogMessage)
        {
            return (ChallengeLogMessage)o;
        }
        else if (o != null)
        {
            return new ChallengeLogMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(index));
        v.add(new ASN1Integer(sequenceNo));
        v.add(ASN1Boolean.getInstance(hasPassed));
        v.add(new ASN1Integer(m));
        v.add(keyInfo);
        v.add(new PointSequence(sourceMessage));
        v.add(new PointSequence(challengeResult));

        return new DERSequence(v);
    }

    public boolean hasPassed()
    {
        return hasPassed;
    }

    public ECPoint[] getSourceMessage()
    {
        return sourceMessage;
    }

    public ECPoint[] getProofs()
    {
        return challengeResult;
    }

    public BigInteger getM()
    {
        return m;
    }

    public SubjectPublicKeyInfo getKeyInfo()
    {
        return keyInfo;
    }

    public int getIndex()
    {
        return index;
    }

    public int getSequenceNo()
    {
        return sequenceNo;
    }
}
