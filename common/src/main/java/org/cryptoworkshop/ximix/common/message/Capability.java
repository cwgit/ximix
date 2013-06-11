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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;

public class Capability
    extends ASN1Object
{
    public static enum Type
        implements MessageType
    {
        BOARD_HOSTING,
        ENCRYPTION,
        KEY_RETRIEVAL,
        KEY_GENERATION,
        SIGNING
    }

    private final Type type;
    private final ASN1Encodable[] details;

    public Capability(Type type, ASN1Encodable[] details)
    {
        this.type = type;
        this.details = details;
    }

    private Capability(ASN1Sequence s)
    {
        this.type = Type.values()[ASN1Enumerated.getInstance(s.getObjectAt(0)).getValue().intValue()];
        this.details = convertSet(ASN1Set.getInstance(s.getObjectAt(1)));
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Enumerated(type.ordinal()));
        v.add(new DERSet(details));

        return new DERSequence(v);
    }

    private ASN1Encodable[] convertSet(ASN1Set strings)
    {
        ASN1Encodable[] rv = new ASN1Encodable[strings.size()];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = strings.getObjectAt(i);
        }

        return rv;
    }
    
    public static Capability getInstance(Object o)
    {
        if (o instanceof Capability)
        {
            return (Capability)o;
        }
        else if (o != null)
        {
            return new Capability(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public Type getType()
    {
        return type;
    }

    public ASN1Encodable[] getDetails()
    {
        return details.clone();
    }
}
