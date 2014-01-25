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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * Request message to fetch a generated seed value.
 */
public class SeedMessage
    extends ASN1Object
{
    private final String boardName;
    private final long   operationNumber;

    /**
     * Base constructor.
     *
     * @param boardName the name of the board the seed is associated with.
     * @param operationNumber the operation number the seed is associated with.
     */
    public SeedMessage(String boardName, long operationNumber)
    {
        this.boardName = boardName;
        this.operationNumber = operationNumber;
    }

    private SeedMessage(ASN1Sequence sequence)
    {
        this.boardName = DERUTF8String.getInstance(sequence.getObjectAt(0)).getString();
        this.operationNumber = ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue().longValue();
    }

    public static final SeedMessage getInstance(Object o)
    {
        if (o instanceof SeedMessage)
        {
            return (SeedMessage)o;
        }
        else if (o != null)
        {
            return new SeedMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(boardName));
        v.add(new ASN1Integer(operationNumber));

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
}
