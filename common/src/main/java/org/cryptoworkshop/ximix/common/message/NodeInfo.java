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
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;

public class NodeInfo
    extends ASN1Object
{
    private final String name;
    private final Capability[] capabilities;

    public NodeInfo(String name, Capability[] capabilities)
    {
        this.name = name;
        this.capabilities = capabilities;
    }

    private NodeInfo(ASN1Sequence s)
    {
        this.name = DERUTF8String.getInstance(s.getObjectAt(0)).getString();
        this.capabilities = convertSet(ASN1Set.getInstance(s.getObjectAt(1)));
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(name));
        v.add(new DERSet(capabilities));

        return new DERSequence(v);
    }

    private Capability[] convertSet(ASN1Set strings)
    {
        Capability[] rv = new Capability[strings.size()];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = Capability.getInstance(strings.getObjectAt(i));
        }

        return rv;
    }
    
    public static NodeInfo getInstance(Object o)
    {
        if (o instanceof NodeInfo)
        {
            return (NodeInfo)o;
        }
        else if (o != null)
        {
            return new NodeInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public String getName()
    {
        return name;
    }

    public Capability[] getCapabilities()
    {
        return capabilities.clone();
    }
}
