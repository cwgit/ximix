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

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * General carrier for an EC point.
 */
public class ECPointMessage
    extends ASN1Object
{
    private final ECPoint point;

    /**
     * Base constructor.
     *
     * @param point the point value to carry.
     */
    public ECPointMessage(ECPoint point)
    {
        this.point = point;
    }

    /**
     * Return the ECPointMessage represented by the passed in object.
     *
     * @param curve the curve the point should reside on.
     * @param o the carrier of the ECPoint, may be an ASN.1 primitive,or an ECPointMessage.
     * @return an instance of an ECPointMessage
     */
    public static ECPointMessage getInstance(ECCurve curve, Object o)
    {
        if (o instanceof ECPointMessage)
        {
            return (ECPointMessage)o;
        }
        if (o != null)
        {
            byte[] encX = ASN1OctetString.getInstance(o).getOctets();

            return new ECPointMessage(curve.decodePoint(encX));
        }

        return null;
    }

    /**
     * <pre>
     * OCTET STRING  value.
     * </pre>
     * @return the ASN.1 primitive representing this object.
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DEROctetString(point.getEncoded());
    }

    public ECPoint getPoint()
    {
        return point;
    }
}
