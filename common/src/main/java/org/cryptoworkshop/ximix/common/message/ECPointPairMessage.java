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
package org.cryptoworkshop.ximix.common.message;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class ECPointPairMessage
    extends ASN1Object
{
    private final ECPoint a;
    private final ECPoint b;

    public ECPointPairMessage(ECPoint a, ECPoint b)
    {
        this.a = a;
        this.b = b;
    }

    private ECPointPairMessage(ECCurve curve, ASN1Sequence seq)
    {
        this.a = curve.decodePoint(ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());
        this.b = curve.decodePoint(ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());
    }

    public static ECPointPairMessage getInstance(ECCurve curve, Object o)
    {
        if (o instanceof ECPointPairMessage)
        {
            return (ECPointPairMessage)o;
        }

        if (o != null)
        {
            return new ECPointPairMessage(curve, ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DEROctetString(a.getEncoded()));
        v.add(new DEROctetString(b.getEncoded()));

        return new DERSequence(v);
    }

    public ECPoint getA()
    {
        return a;
    }

    public ECPoint getB()
    {
        return b;
    }
}
