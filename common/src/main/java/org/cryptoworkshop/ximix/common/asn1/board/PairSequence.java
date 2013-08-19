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
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECCurve;

/**
 * Helper class for carrying an array of EC pairs.
 */
public class PairSequence
    extends ASN1Object
{
    private final ECPair[] ecPairs;

    /**
     * Create a sequence from a single pair.
     *
     * @param ecPair the pair to include
     */
    public PairSequence(ECPair ecPair)
    {
        this.ecPairs = new ECPair[] { ecPair };
    }

    /**
     * Create a sequence from a collection of pairs.
     *
     * @param ecPairs the pairs to include.
     */
    public PairSequence(ECPair... ecPairs)
    {
        this.ecPairs = ecPairs.clone();
    }

    private PairSequence(ECCurve curve, ASN1Sequence s)
    {
        ecPairs = new ECPair[s.size()];

        for (int i = 0; i != ecPairs.length; i++)
        {
            ecPairs[i] = Pair.getInstance(curve, s.getObjectAt(i)).getECPair();
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
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (ECPair pair : ecPairs)
        {
            v.add(new Pair(pair));
        }

        return new DERSequence(v);
    }

    /**
     * Reconstruct a PairSequence from it's ASN.1 representation.
     *
     * @param curve the curve that the points in the sequence belong to.
     * @param o the sequence object.
     * @return a constructed EC pair sequence.
     */
    public static PairSequence getInstance(ECCurve curve, Object o)
    {
        if (o instanceof PairSequence)
        {
            return (PairSequence)o;
        }
        if (o != null)
        {
            return new PairSequence(curve, ASN1Sequence.getInstance(o));
        }

        return null;
    }

    /**
     * Return the EC pairs held in this sequence.
     *
     * @return an array of EC pairs.
     */
    public ECPair[] getECPairs()
    {
        return ecPairs;
    }

    /**
     * Return the number of pairs contained in the sequence.
     *
     * @return the size of the sequence.
     */
    public int size()
    {
        return ecPairs.length;
    }
}
