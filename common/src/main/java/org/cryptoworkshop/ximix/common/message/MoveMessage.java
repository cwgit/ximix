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

public class MoveMessage
    extends ASN1Object
{
    private final String nodeName;
    private final String boardName;

    public MoveMessage(String nodeName, String boardName)
    {
        this.nodeName = nodeName;
        this.boardName = boardName;
    }

    private MoveMessage(ASN1Sequence seq)
    {
        this.nodeName = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
        this.boardName = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
    }

    public static final MoveMessage getInstance(Object o)
    {
        if (o instanceof MoveMessage)
        {
            return (MoveMessage)o;
        }
        else if (o != null)
        {
            return new MoveMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(nodeName));
        v.add(new DERUTF8String(boardName));

        return new DERSequence(v);
    }

    public String getNodeName()
    {
        return boardName;
    }

    public String getBoardName()
    {
        return boardName;
    }
}
