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
package org.cryptoworkshop.ximix.common.messages;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

public class UploadMessage
    extends ASN1Object
{
    private final String boardName;
    private final byte[] data;

    public UploadMessage(String boardName, byte[] data)
    {
        this.boardName = boardName;
        this.data = data.clone();
    }

    private UploadMessage(ASN1Sequence seq)
    {
        this.boardName = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
        this.data = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
    }

    public static final UploadMessage getInstance(Object o)
    {
        if (o instanceof UploadMessage)
        {
            return (UploadMessage)o;
        }
        else if (o != null)
        {
            return new UploadMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(boardName));
        v.add(new DEROctetString(data));

        return new DERSequence(v);
    }

    public String getBoardName()
    {
        return boardName;
    }

    public byte[] getData()
    {
        return data;
    }
}
