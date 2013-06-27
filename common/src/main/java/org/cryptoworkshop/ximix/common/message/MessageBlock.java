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

public class MessageBlock
    extends ASN1Object
{
    private final List<byte[]> messages;

    public MessageBlock(List<byte[]> messages)
    {
        this.messages = messages;
    }

    private MessageBlock(ASN1Sequence seq)
    {
        messages = new ArrayList<>(seq.size());

        for (Enumeration en = seq.getObjects(); en.hasMoreElements();)
        {
            this.messages.add(ASN1OctetString.getInstance(en.nextElement()).getOctets());
        }
    }

    public static final MessageBlock getInstance(Object o)
    {
        if (o instanceof MessageBlock)
        {
            return (MessageBlock)o;
        }
        else if (o != null)
        {
            return new MessageBlock(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (byte[] message : messages)
        {
            v.add(new DEROctetString(message));
        }

        return new DERSequence(v);
    }

    public List<byte[]> getMessages()
    {
        return messages;
    }

    public int size()
    {
        return messages.size();
    }
}
