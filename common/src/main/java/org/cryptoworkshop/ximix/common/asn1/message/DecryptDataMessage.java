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

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * Carrier message for a block of messages to have a decryption process applied to.
 */
public class DecryptDataMessage
    extends ASN1Object
{
    private final List<byte[]> messages;
    private final String keyID;

    /**
     * Base constructor.
     *
     * @param keyID the ID of the private key to decrypt against.
     * @param messages a list of messages to be decrypted.
     */
    public DecryptDataMessage(String keyID, List<byte[]> messages)
    {
        this.keyID = keyID;
        this.messages = messages;
    }

    private DecryptDataMessage(ASN1Sequence seq)
    {
        this.keyID = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
        messages = new ArrayList<>(seq.size());

        for (Enumeration en = ASN1Sequence.getInstance(seq.getObjectAt(1)).getObjects(); en.hasMoreElements();)
        {
            this.messages.add(ASN1OctetString.getInstance(en.nextElement()).getOctets());
        }
    }

    public static final DecryptDataMessage getInstance(Object o)
    {
        if (o instanceof DecryptDataMessage)
        {
            return (DecryptDataMessage)o;
        }
        else if (o != null)
        {
            return new DecryptDataMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        ASN1EncodableVector mv = new ASN1EncodableVector();

        for (byte[] message : messages)
        {
            mv.add(new DEROctetString(message));
        }

        v.add(new DERUTF8String(keyID));
        v.add(new DERSequence(mv));

        return new DERSequence(v);
    }

    public List<byte[]> getMessages()
    {
        return messages;
    }

    public String getKeyID()
    {
        return keyID;
    }
}
