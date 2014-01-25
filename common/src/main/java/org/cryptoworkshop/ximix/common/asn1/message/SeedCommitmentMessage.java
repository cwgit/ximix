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
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * Carrier message containing the commitment value for a seed for a particular board operation.
 */
public class SeedCommitmentMessage
    extends ASN1Object
{
    private final String boardName;
    private final long   operationNumber;
    private final byte[] commitment;

    /**
     * Base constructor.
     *
     * @param boardName the name of the board the commitment is associated with.
     * @param operationNumber the operation number the commitment is associated with.
     * @param commitment the seed commitment.
     */
    public SeedCommitmentMessage(String boardName, long operationNumber, byte[] commitment)
    {
        this.boardName = boardName;
        this.operationNumber = operationNumber;
        this.commitment = commitment;
    }

    private SeedCommitmentMessage(ASN1Sequence sequence)
    {
        this.boardName = DERUTF8String.getInstance(sequence.getObjectAt(0)).getString();
        this.operationNumber = ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue().longValue();
        this.commitment = ASN1OctetString.getInstance(sequence.getObjectAt(2)).getOctets();
    }

    public static final SeedCommitmentMessage getInstance(Object o)
    {
        if (o instanceof SeedCommitmentMessage)
        {
            return (SeedCommitmentMessage)o;
        }
        else if (o != null)
        {
            return new SeedCommitmentMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(boardName));
        v.add(new ASN1Integer(operationNumber));
        v.add(new DEROctetString(commitment));

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

    public byte[] getCommitment()
    {
        return commitment;
    }
}
