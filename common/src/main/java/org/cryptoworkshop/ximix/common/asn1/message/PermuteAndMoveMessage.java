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

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

public class PermuteAndMoveMessage
    extends ASN1Object
{
    private final long operationNumber;
    private final String boardName;
    private final int stepNumber;
    private final String keyID;
    private final String nodeName;
    private final String transformName;

    public PermuteAndMoveMessage(long operationNumber, String boardName, int stepNumber, String transformName, String keyID, String nodeName)
    {
        this.operationNumber = operationNumber;
        this.boardName = boardName;
        this.stepNumber = stepNumber;
        this.transformName = transformName;
        this.keyID = keyID;
        this.nodeName = nodeName;
    }

    private PermuteAndMoveMessage(ASN1Sequence seq)
    {
        this.operationNumber = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().longValue();
        this.boardName = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
        this.stepNumber = ASN1Integer.getInstance(seq.getObjectAt(2)).getValue().intValue();
        this.transformName = DERUTF8String.getInstance(seq.getObjectAt(3)).getString();

        if (seq.size() == 6)
        {
            this.keyID = DERUTF8String.getInstance(seq.getObjectAt(4)).getString();
            this.nodeName = DERUTF8String.getInstance(seq.getObjectAt(5)).getString();
        }
        else
        {
            this.keyID = null;
            this.nodeName = DERUTF8String.getInstance(seq.getObjectAt(4)).getString();
        }
    }

    public static final PermuteAndMoveMessage getInstance(Object o)
    {
        if (o instanceof PermuteAndMoveMessage)
        {
            return (PermuteAndMoveMessage)o;
        }
        else if (o != null)
        {
            return new PermuteAndMoveMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(BigInteger.valueOf(operationNumber)));
        v.add(new DERUTF8String(boardName));
        v.add(new ASN1Integer(BigInteger.valueOf(stepNumber)));
        v.add(new DERUTF8String(transformName));

        if (keyID != null)
        {
            v.add(new DERUTF8String(keyID));
        }

        v.add(new DERUTF8String(nodeName));

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

    public long getOperationNumber()
    {
        return operationNumber;
    }

    public int getStepNumber()
    {
        return stepNumber;
    }

    public String getTransformName()
    {
        return transformName;
    }

    public String getDestinationNode()
    {
        return nodeName;
    }
}
