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
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class PointSequence
    extends ASN1Object
{
    private final ECPoint[] ecPoints;

    public PointSequence(ECPoint ecPoint)
    {
        this.ecPoints = new ECPoint[] { ecPoint };
    }

    public PointSequence(ECPoint... ecPoints)
    {
        this.ecPoints = ecPoints.clone();
    }

    private PointSequence(ECCurve curve, ASN1Sequence s)
    {
        ecPoints = new ECPoint[s.size()];

        for (int i = 0; i != ecPoints.length; i++)
        {
            ecPoints[i] = curve.decodePoint(ASN1OctetString.getInstance(s.getObjectAt(i)).getOctets());
        }
    }

    /**
     * <pre>
     *     PointSequence ::= SEQUENCE OF Point
     * </pre>
     *
     * @return an encoding of an ASN.1 sequence
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (ECPoint point : ecPoints)
        {
            v.add(new DEROctetString(point.getEncoded()));
        }

        return new DERSequence(v);
    }

    public static PointSequence getInstance(ECCurve curve, Object o)
    {
        if (o instanceof PointSequence)
        {
            return (PointSequence)o;
        }
        if (o != null)
        {
            return new PointSequence(curve, ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ECPoint[] getECPoints()
    {
        return ecPoints;
    }

    public int size()
    {
        return ecPoints.length;
    }
}
