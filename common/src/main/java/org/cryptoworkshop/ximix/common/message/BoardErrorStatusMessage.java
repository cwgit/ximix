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
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

public class BoardErrorStatusMessage
    extends ASN1Object
{
    private final String boardName;
    private final Status status;

    public enum Status
    {
        NOT_DOWNLOAD_LOCKED, NOT_SHUFFLE_LOCKED, SUSPENDED
    }

    public BoardErrorStatusMessage(String boardName, Status status)
    {
        this.boardName = boardName;
        this.status = status;
    }

    private BoardErrorStatusMessage(ASN1Sequence seq)
    {
        this.boardName = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
        this.status = Status.values()[ASN1Enumerated.getInstance(seq.getObjectAt(1)).getValue().intValue()];
    }

    public static final BoardErrorStatusMessage getInstance(Object o)
    {
        if (o instanceof BoardErrorStatusMessage)
        {
            return (BoardErrorStatusMessage)o;
        }
        else if (o != null)
        {
            return new BoardErrorStatusMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(boardName));
        v.add(new ASN1Enumerated(status.ordinal()));

        return new DERSequence(v);
    }

    public String getBoardName()
    {
        return boardName;
    }

    public Status getStatus()
    {
        return status;
    }
}
