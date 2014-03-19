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

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptoworkshop.ximix.common.asn1.board.PointSequence;
import org.cryptoworkshop.ximix.common.crypto.ECDecryptionProof;

/**
 * Class used to define the fields in a decryption challenge log message.
 */
public class ChallengeLogMessage
    extends ASN1Object
{
    private final int index;
    private final int sequenceNo;
    private final boolean hasPassed;
    private final SubjectPublicKeyInfo keyInfo;
    private final ECPoint[] sourceMessage;
    private final ECDecryptionProof[] decryptionProofs;

    /**
     * Base constructor.
     *
     * @param index the index number of the message challenged.
     * @param sequenceNo the sequenceNo in the sharing process for the node this message is based on.
     * @param hasPassed
     * @param keyInfo the node's partial public key.
     * @param sourceMessage the input message for the challenge computation.
     * @param decryptionProofs decryption proofs..
     */
    public ChallengeLogMessage(int index, int sequenceNo, boolean hasPassed, SubjectPublicKeyInfo keyInfo, ECPoint[] sourceMessage, ECDecryptionProof[] decryptionProofs)
    {
        this.index = index;
        this.sequenceNo = sequenceNo;
        this.hasPassed = hasPassed;
        this.keyInfo = keyInfo;
        this.sourceMessage = sourceMessage;
        this.decryptionProofs = decryptionProofs;
    }

    private ChallengeLogMessage(ASN1Sequence seq)
    {
        this.index = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().intValue();
        this.sequenceNo = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue().intValue();
        this.hasPassed = ASN1Boolean.getInstance(seq.getObjectAt(2)).isTrue();
        this.keyInfo = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(3));

        ECPublicKeyParameters ecKey;
        try
        {
            ecKey = (ECPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("Unable to create EC key from keyInfo in sequence.");
        }

        ECCurve curve = ecKey.getParameters().getCurve();

        this.sourceMessage = PointSequence.getInstance(curve, ASN1Sequence.getInstance(seq.getObjectAt(4))).getECPoints();

        ASN1Sequence proofS = ASN1Sequence.getInstance(seq.getObjectAt(5));
        decryptionProofs = new ECDecryptionProof[proofS.size()];

        for (int i = 0; i != decryptionProofs.length; i++)
        {
            ASN1Sequence proof = ASN1Sequence.getInstance(proofS.getObjectAt(i));
            decryptionProofs[i] = new ECDecryptionProof(curve.decodePoint(ASN1OctetString.getInstance(proof.getObjectAt(0)).getOctets()),
                curve.decodePoint(ASN1OctetString.getInstance(proof.getObjectAt(1)).getOctets()), ASN1Integer.getInstance(proof.getObjectAt(2)).getValue());
        }
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
        v.add(keyInfo);
        v.add(new PointSequence(sourceMessage));

        ASN1EncodableVector dv = new ASN1EncodableVector();
        for (ECDecryptionProof proof : decryptionProofs)
        {
            ASN1EncodableVector proofV = new ASN1EncodableVector();

            proofV.add(new DEROctetString(proof.getA().getEncoded(true)));
            proofV.add(new DEROctetString(proof.getB().getEncoded(true)));
            proofV.add(new ASN1Integer(proof.getR()));

            dv.add(new DERSequence(proofV));
        }

        v.add(new DERSequence(dv));

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

    public ECDecryptionProof[] getProofs()
    {
        return decryptionProofs;
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
