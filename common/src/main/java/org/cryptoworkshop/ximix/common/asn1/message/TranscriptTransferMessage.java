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
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

/**
 * Carrier for a fragment of a transcript
 */
public class TranscriptTransferMessage
    extends ASN1Object
{
    private final int stepNo;
    private final byte[] chunk;

    /**
     * Create a message for a particular step number with zero or more bytes of data.
     *
     * @param stepNo file name data belongs to.
     * @param chunk the data to be appended.
     */
    public TranscriptTransferMessage(int stepNo, byte[] chunk)
    {
        this.stepNo = stepNo;
        this.chunk = chunk;
    }

    /**
     * Create an END OF TRANSFER message.
     *
     * @param stepNo step number we are signaling end of transfer for..
     */
    public TranscriptTransferMessage(int stepNo)
    {
        this.stepNo = stepNo;
        this.chunk = null;
    }

    private TranscriptTransferMessage(ASN1Sequence sequence)
    {
        this.stepNo = ASN1Integer.getInstance(sequence.getObjectAt(0)).getValue().intValue();
        if (sequence.size() > 1)
        {
            this.chunk = DEROctetString.getInstance(sequence.getObjectAt(1)).getOctets();
        }
        else
        {
            this.chunk = null;
        }
    }

    public static TranscriptTransferMessage getInstance(Object o)
    {
        if (o instanceof TranscriptTransferMessage)
        {
            return (TranscriptTransferMessage)o;
        }
        else if (o != null)
        {
            return new TranscriptTransferMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public int getStepNo()
    {
        return stepNo;
    }

    public boolean isEndOfTransfer()
    {
        return chunk == null;
    }

    public byte[] getChunk()
    {
        return chunk;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(stepNo));

        if (chunk != null)
        {
            v.add(new DEROctetString(chunk));
        }

        return new DERSequence(v);
    }
}
