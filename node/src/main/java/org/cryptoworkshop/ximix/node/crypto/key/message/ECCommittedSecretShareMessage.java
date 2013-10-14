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
package org.cryptoworkshop.ximix.node.crypto.key.message;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Carrier class for a BLS secret share with a commitment.
 */
public class ECCommittedSecretShareMessage
    extends ASN1Object
{
    private final int        index;
    private final BigInteger value;
    private final BigInteger witness;
    private final ECPoint[] commitmentFactors;
    private final ECPoint q;
    private final ECPoint[] qCommitmentFactors;


    /**
     * Base constructor.
     *
     * @param index sequence number of the share.
     * @param value share value.
     * @param witness witness value associated with share.
     * @param commitmentFactors commitment factors associated with share.
     * @param q the public value associated with the secret.
     */
    public ECCommittedSecretShareMessage(int index, BigInteger value, BigInteger witness, ECPoint[] commitmentFactors, ECPoint q, ECPoint[] qCommitmentFactors)
    {
        this.index = index;
        this.value = value;
        this.witness = witness;
        this.commitmentFactors = commitmentFactors;
        this.q = q;
        this.qCommitmentFactors = qCommitmentFactors;
    }

    private ECCommittedSecretShareMessage(ECCurve curve, ASN1Sequence seq)
    {
        this.index = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().intValue();
        this.value = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
        this.witness = ASN1Integer.getInstance(seq.getObjectAt(2)).getValue();

        ASN1Sequence pSeq = ASN1Sequence.getInstance(seq.getObjectAt(3));

        this.commitmentFactors = new ECPoint[pSeq.size()];

        for (int i = 0; i != commitmentFactors.length; i++)
        {
            byte[] enc = ASN1OctetString.getInstance(pSeq.getObjectAt(i)).getOctets();

            commitmentFactors[i] = curve.decodePoint(enc);
        }

        this.q = curve.decodePoint(ASN1OctetString.getInstance(seq.getObjectAt(4)).getOctets());

        ASN1Sequence qSeq = ASN1Sequence.getInstance(seq.getObjectAt(5));

        this.qCommitmentFactors = new ECPoint[qSeq.size()];

        for (int i = 0; i != commitmentFactors.length; i++)
        {
            byte[] enc = ASN1OctetString.getInstance(qSeq.getObjectAt(i)).getOctets();

            qCommitmentFactors[i] = curve.decodePoint(enc);
        }
    }

    public static final ECCommittedSecretShareMessage getInstance(ECCurve curve, Object o)
    {
        if (o instanceof ECCommittedSecretShareMessage)
        {
            return (ECCommittedSecretShareMessage)o;
        }
        else if (o != null)
        {
            return new ECCommittedSecretShareMessage(curve, ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(index));
        v.add(new ASN1Integer(value));
        v.add(new ASN1Integer(witness));

        ASN1EncodableVector factV = new ASN1EncodableVector();
        for (int i = 0; i != commitmentFactors.length; i++)
        {
            factV.add(new DEROctetString(commitmentFactors[i].getEncoded()));
        }

        v.add(new DERSequence(factV));
        v.add(new DEROctetString(q.getEncoded()));

        ASN1EncodableVector qFactV = new ASN1EncodableVector();
        for (int i = 0; i != qCommitmentFactors.length; i++)
        {
            qFactV.add(new DEROctetString(qCommitmentFactors[i].getEncoded()));
        }

        v.add(new DERSequence(qFactV));

        return new DERSequence(v);
    }

    public ECPoint[] getCommitmentFactors()
    {
        return commitmentFactors;
    }

    public int getIndex()
    {
        return index;
    }

    public BigInteger getValue()
    {
        return value;
    }

    public BigInteger getWitness()
    {
        return witness;
    }

    public ECPoint getQ()
    {
        return q;
    }

    public ECPoint[] getQCommitmentFactors()
    {
        return qCommitmentFactors;
    }
}
