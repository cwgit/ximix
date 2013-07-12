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
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

public class PermuteAndReturnMessage
    extends ASN1Object
{
    private final String boardName;
    private final String keyID;
    private final String transformName;

    public PermuteAndReturnMessage(String boardName, String transformName, String keyID)
    {
        this.boardName = boardName;
        this.transformName = transformName;
        this.keyID = keyID;
    }

    private PermuteAndReturnMessage(ASN1Sequence seq)
    {
        if (seq.size() == 3)
        {
            this.boardName = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
            this.transformName = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
            this.keyID = DERUTF8String.getInstance(seq.getObjectAt(2)).getString();
        }
        else
        {
            this.boardName = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
            this.transformName = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
            this.keyID = null;
        }
    }

    public static final PermuteAndReturnMessage getInstance(Object o)
    {
        if (o instanceof PermuteAndReturnMessage)
        {
            return (PermuteAndReturnMessage)o;
        }
        else if (o != null)
        {
            return new PermuteAndReturnMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(boardName));
        v.add(new DERUTF8String(transformName));

        if (keyID != null)
        {
            v.add(new DERUTF8String(keyID));
        }

        return new DERSequence(v);
    }

    public String getKeyID()
    {
        return keyID;
    }

    public String getBoardName()
    {
        return boardName;
    }

    public String getTransformName()
    {
        return transformName;
    }
}
