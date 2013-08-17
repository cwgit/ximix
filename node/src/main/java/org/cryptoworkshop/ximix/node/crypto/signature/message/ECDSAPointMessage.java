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
package org.cryptoworkshop.ximix.node.crypto.signature.message;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.math.ec.ECPoint;

public class ECDSAPointMessage
    extends ASN1Object
{
    private final String keyID;
    private final byte[] point;

    public ECDSAPointMessage(String keyID, ECPoint point)
    {
        this.keyID = keyID;
        this.point = point.getEncoded();
    }

    private ECDSAPointMessage(ASN1Sequence seq)
    {
        this.keyID = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
        this.point = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
    }

    public static ECDSAPointMessage getInstance(Object o)
    {
        if (o instanceof ECDSAPointMessage)
        {
            return (ECDSAPointMessage)o;
        }
        if (o != null)
        {
            return new ECDSAPointMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(keyID));
        v.add(new DEROctetString(point));

        return new DERSequence(v);
    }

    public String getKeyID()
    {
        return keyID;
    }

    public byte[] getPoint()
    {
        return point;
    }
}