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
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * Carrier class for information related to a node - its name and capabilities.
 */
public class NodeInfo
    extends ASN1Object
{
    private final String name;
    private final CapabilityMessage[] capabilities;

    /**
     * Base constructor.
     *
     * @param name the name of the node associated with this info message.
     * @param capabilities an array of CapabilityMessage giving the capabilities of the node.
     */
    public NodeInfo(String name, CapabilityMessage[] capabilities)
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

    private CapabilityMessage[] convertSet(ASN1Set strings)
    {
        CapabilityMessage[] rv = new CapabilityMessage[strings.size()];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = CapabilityMessage.getInstance(strings.getObjectAt(i));
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

    public CapabilityMessage[] getCapabilities()
    {
        return capabilities.clone();
    }
}
