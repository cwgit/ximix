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
package org.cryptoworkshop.ximix.common.asn1.board;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Helper class for carrying an array of EC pairs with associated proofs of decryption.
 */
public class PairSequenceWithProofs
    extends ASN1Object
{
    private final ECPair[] ecPairs;
    private final ECPoint[] ecProofs;

    /**
     * Create a sequence from a collection of pairs representing partial decrypts.
     *
     * @param ecPairs the pairs to include.
     * @param ecProofs proofs of decryption associated with each pair
     */
    public PairSequenceWithProofs(ECPair[] ecPairs, ECPoint[] ecProofs)
    {
        this.ecPairs = ecPairs.clone();
        this.ecProofs = ecProofs.clone();
    }

    private PairSequenceWithProofs(ECCurve curve, ASN1Sequence sequence)
    {
        ASN1Sequence s = ASN1Sequence.getInstance(sequence.getObjectAt(0));

        ecPairs = new ECPair[s.size()];

        for (int i = 0; i != ecPairs.length; i++)
        {
            ecPairs[i] = Pair.getInstance(curve, s.getObjectAt(i)).getECPair();
        }

        s = ASN1Sequence.getInstance(sequence.getObjectAt(1));
        ecProofs = new ECPoint[s.size()];

        for (int i = 0; i != ecPairs.length; i++)
        {
            ecProofs[i] = curve.decodePoint(ASN1OctetString.getInstance(s.getObjectAt(i)).getOctets());
        }
    }

    /**
     * <pre>
     *     PairSequence ::= SEQUENCE OF Pair
     * </pre>
     *
     * @return an encoding of an ASN.1 sequence
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector tot = new ASN1EncodableVector();
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (ECPair pair : ecPairs)
        {
            v.add(new Pair(pair));
        }

        tot.add(new DERSequence(v));

        v = new ASN1EncodableVector();
        for (ECPoint point : ecProofs)
        {
            v.add(new DEROctetString(point.getEncoded()));
        }

        tot.add(new DERSequence(v));

        return new DERSequence(tot);
    }

    /**
     * Reconstruct a PairSequence from it's ASN.1 representation.
     *
     * @param curve the curve that the points in the sequence belong to.
     * @param o the sequence object.
     * @return a constructed EC pair sequence.
     */
    public static PairSequenceWithProofs getInstance(ECCurve curve, Object o)
    {
        if (o instanceof PairSequenceWithProofs)
        {
            return (PairSequenceWithProofs)o;
        }
        if (o != null)
        {
            return new PairSequenceWithProofs(curve, ASN1Sequence.getInstance(o));
        }

        return null;
    }

    /**
     * Return the EC partial decrypts held in this object.
     *
     * @return an array of EC pairs.
     */
    public ECPair[] getECPairs()
    {
        return ecPairs;
    }

    /**
     * Return the EC proofs associated with the pairs in this object.
     *
     * @return an array of EC points representing proofs.
     */
    public ECPoint[] getECProofs()
    {
        return ecProofs;
    }

    /**
     * Return the number of pairs contained in the object.
     *
     * @return the size of the sequence.
     */
    public int size()
    {
        return ecPairs.length;
    }
}
