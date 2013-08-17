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

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.cryptoworkshop.ximix.node.crypto.util.Participant;

public class BLSPartialCreateMessage
    extends ASN1Object
{
    private final String sigID;
    private final String keyID;
    private final Participant[] nodesToUse;
    private final ASN1OctetString h;

    public BLSPartialCreateMessage(String sigID, String keyID, Element h, Participant[] nodesToUse)
    {
        this.sigID = sigID;
        this.keyID = keyID;
        this.h = new DEROctetString(h.toBytes());
        this.nodesToUse = nodesToUse;
    }

    private BLSPartialCreateMessage(ASN1Sequence seq)
    {
        this.sigID = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
        this.keyID = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
        this.h = ASN1OctetString.getInstance(seq.getObjectAt(2));
        this.nodesToUse = MessageUtils.toArray(ASN1Sequence.getInstance(seq.getObjectAt(3)));
    }

    public static final BLSPartialCreateMessage getInstance(Object o)
    {
        if (o instanceof BLSPartialCreateMessage)
        {
            return (BLSPartialCreateMessage)o;
        }
        else if (o != null)
        {
            return new BLSPartialCreateMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(sigID));
        v.add(new DERUTF8String(keyID));
        v.add(h);
        v.add(MessageUtils.toASN1Sequence(nodesToUse));

        return new DERSequence(v);
    }

    public String getSigID()
    {
        return sigID;
    }

    public String getKeyID()
    {
        return keyID;
    }

    public Element getH(Pairing pairing)
    {
        Element G = pairing.getG1().newElement();
        G.setFromBytes(h.getOctets());

        return G;
    }

    public Participant[] getNodesToUse()
    {
        return nodesToUse;
    }

}
