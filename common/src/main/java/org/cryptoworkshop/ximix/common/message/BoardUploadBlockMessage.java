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
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

public class BoardUploadBlockMessage
    extends ASN1Object
{
    private final String boardName;
    private final PostedMessageBlock messageBlock;
    private final int stepNumber;
    private final long operationNumber;

    public BoardUploadBlockMessage(long operationNumber, String boardName, int stepNumber, PostedMessageBlock messageBlock)
    {
        this.operationNumber = operationNumber;
        this.boardName = boardName;
        this.stepNumber = stepNumber;
        this.messageBlock = messageBlock;
    }

    private BoardUploadBlockMessage(ASN1Sequence seq)
    {
        this.operationNumber = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().longValue();
        this.boardName = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
        this.stepNumber = ASN1Integer.getInstance(seq.getObjectAt(2)).getValue().intValue();
        this.messageBlock = PostedMessageBlock.getInstance(seq.getObjectAt(3));
    }

    public static final BoardUploadBlockMessage getInstance(Object o)
    {
        if (o instanceof BoardUploadBlockMessage)
        {
            return (BoardUploadBlockMessage)o;
        }
        else if (o != null)
        {
            return new BoardUploadBlockMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(operationNumber));
        v.add(new DERUTF8String(boardName));
        v.add(new ASN1Integer(stepNumber));
        v.add(messageBlock);

        return new DERSequence(v);
    }

    public String getBoardName()
    {
        return boardName;
    }

    public PostedMessageBlock getMessageBlock()
    {
        return messageBlock;
    }

    public long getOperationNumber()
    {
        return operationNumber;
    }

    public int getStepNumber()
    {
        return stepNumber;
    }
}
