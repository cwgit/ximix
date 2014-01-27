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

/**
 * Request message for a copy and move operation on a bulletin board.
 */
public class CopyAndMoveMessage
    extends ASN1Object
{
    private final long operationNumber;
    private final String boardName;
    private final int stepNumber;
    private final String nodeName;

    /**
     * Base constructor.
     *
     * @param operationNumber the operation number this request is associated with.
     * @param boardName the name of the board this operation is associated with.
     * @param stepNumber the step number in the operation this message is associated with.
     * @param nodeName the name of the node to send the copied messages to.
     */
    public CopyAndMoveMessage(long operationNumber, String boardName, int stepNumber, String nodeName)
    {
        this.operationNumber = operationNumber;
        this.boardName = boardName;
        this.stepNumber = stepNumber;
        this.nodeName = nodeName;
    }

    private CopyAndMoveMessage(ASN1Sequence seq)
    {
        this.operationNumber = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().longValue();
        this.boardName = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
        this.stepNumber = ASN1Integer.getInstance(seq.getObjectAt(2)).getValue().intValue();
        this.nodeName = DERUTF8String.getInstance(seq.getObjectAt(3)).getString();
    }

    public static final CopyAndMoveMessage getInstance(Object o)
    {
        if (o instanceof CopyAndMoveMessage)
        {
            return (CopyAndMoveMessage)o;
        }
        else if (o != null)
        {
            return new CopyAndMoveMessage(ASN1Sequence.getInstance(o));
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
        v.add(new DERUTF8String(nodeName));

        return new DERSequence(v);
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

    public String getDestinationNode()
    {
        return nodeName;
    }
}
