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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

/**
 * Carrier class for a single byte[] on posted on the message board.
 */
public class PostedData
    extends ASN1Object
{
    private final int    index;
    private final byte[] data;

    private PostedData(ASN1Sequence seq)
    {
        this.index = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().intValue();
        this.data = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
    }

    public PostedData(int index, byte[] data)
    {
        this.index = index;
        this.data = data;
    }

    public static final PostedData getInstance(Object o)
    {
        if (o instanceof PostedData)
        {
            return (PostedData)o;
        }
        else if (o != null)
        {
            return new PostedData(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(index));
        v.add(new DEROctetString(data));

        return new DERSequence(v);
    }

    public int getIndex()
    {
        return index;
    }

    public byte[] getData()
    {
        return data;
    }
}
