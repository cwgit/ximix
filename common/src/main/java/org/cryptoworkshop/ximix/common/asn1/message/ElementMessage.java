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

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;

/**
 * General carrier for a pairing Element.
 */
public class ElementMessage
    extends ASN1Object
{
    private final Element value;

    /**
     * Base constructor.
     *
     * @param value the element value to be carried.
     */
    public ElementMessage(Element value)
    {
        this.value = value;
    }

    private ElementMessage(Pairing pairing, ASN1OctetString octets)
    {
        Element G = pairing.getG1().newElement();
        G.setFromBytes(DEROctetString.getInstance(ASN1OctetString.getInstance(octets)).getOctets());

        this.value = G.getImmutable();
    }

    /**
     * Return the ElementMessage represented by the passed in object.
     *
     * @param pairing the pairing the element is associated with.
     * @param o the carrier of the Element, may be an ASN.1 primitive,or an ElementMessage.
     * @return an instance of an ElementMessage
     */
    public static final ElementMessage getInstance(Pairing pairing, Object o)
    {
        if (o instanceof ElementMessage)
        {
            return (ElementMessage)o;
        }
        else if (o != null)
        {
            return new ElementMessage(pairing, ASN1OctetString.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DEROctetString(value.toBytes());
    }

    public Element getValue()
    {
        return value;
    }
}
