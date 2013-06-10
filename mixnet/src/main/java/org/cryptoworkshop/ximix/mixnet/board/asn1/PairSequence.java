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
package org.cryptoworkshop.ximix.mixnet.board.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECCurve;

public class PairSequence
    extends ASN1Object
{
    private final ECPair[] ecPairs;

    public PairSequence(ECPair ecPair)
    {
        this.ecPairs = new ECPair[] { ecPair };
    }

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

    public ECPair[] getECPairs()
    {
        return ecPairs;
    }
}
