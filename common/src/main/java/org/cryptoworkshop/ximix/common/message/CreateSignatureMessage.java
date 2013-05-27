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
import org.bouncycastle.asn1.DERUTF8String;

public class CreateSignatureMessage
    extends ASN1Object
{
    private String keyID;
    private byte[] hash;

    public CreateSignatureMessage(String keyID, byte[] hash)
    {
        this.keyID = keyID;
        this.hash = hash.clone();
    }

    private CreateSignatureMessage(ASN1Sequence seq)
    {
        this.keyID = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
        this.hash = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets().clone();
    }

    public static final CreateSignatureMessage getInstance(Object o)
    {
        if (o instanceof CreateSignatureMessage)
        {
            return (CreateSignatureMessage)o;
        }
        else if (o != null)
        {
            return new CreateSignatureMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(keyID));
        v.add(new DEROctetString(hash));

        return new DERSequence(v);
    }

    public String getKeyID()
    {
        return keyID;
    }

    public byte[] getHash()
    {
        return hash;
    }
}
