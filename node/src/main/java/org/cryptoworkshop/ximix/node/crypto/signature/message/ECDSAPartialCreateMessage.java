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

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.cryptoworkshop.ximix.node.crypto.util.Participant;

/**
 * Message carrier for instructions to create an ECDSA partial signature.
 */
public class ECDSAPartialCreateMessage
    extends ASN1Object
{
    private final String sigID;
    private final String keyID;
    private final Participant[] nodesToUse;
    private final BigInteger e;

    public ECDSAPartialCreateMessage(String sigID, String keyID, BigInteger e, Participant[] nodesToUse)
    {
        this.sigID = sigID;
        this.keyID = keyID;
        this.e = e;
        this.nodesToUse = nodesToUse;
    }

    private ECDSAPartialCreateMessage(ASN1Sequence seq)
    {
        this.sigID = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
        this.keyID = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
        this.e = ASN1Integer.getInstance(seq.getObjectAt(2)).getValue();
        this.nodesToUse = MessageUtils.toArray(ASN1Sequence.getInstance(seq.getObjectAt(3)));
    }

    public static final ECDSAPartialCreateMessage getInstance(Object o)
    {
        if (o instanceof ECDSAPartialCreateMessage)
        {
            return (ECDSAPartialCreateMessage)o;
        }
        else if (o != null)
        {
            return new ECDSAPartialCreateMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(sigID));
        v.add(new DERUTF8String(keyID));
        v.add(new ASN1Integer(e));
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

    public BigInteger getE()
    {
        return e;
    }

    public Participant[] getNodesToUse()
    {
        return nodesToUse;
    }

}
