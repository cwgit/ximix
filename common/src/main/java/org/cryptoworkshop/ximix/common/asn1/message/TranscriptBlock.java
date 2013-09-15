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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;

/**
 * Carrier class for a block of PostedMessage objects.
 */
public class TranscriptBlock
    extends ASN1Object
{
    private int stepNo;
    private ASN1Sequence details;

    public static class Builder
    {
        private final int stepNo;
        private final int capacity;

        private ASN1EncodableVector details;

        public Builder(int stepNo, int capacity)
        {
            this.stepNo = stepNo;
            this.capacity = capacity;
            this.details = new ASN1EncodableVector();
        }

        public Builder add(ASN1Encodable detail)
        {
            details.add(detail);

            return this;
        }

        public Builder clear()
        {
            details = new ASN1EncodableVector();

            return this;
        }

        public TranscriptBlock build()
        {
            return new TranscriptBlock(stepNo, details);
        }

        public int capacity()
        {
            return capacity;
        }

        public boolean isFull()
        {
            return details.size() == capacity;
        }

        public boolean isEmpty()
        {
            return details.size() == 0;
        }
    }

    private TranscriptBlock(int stepNo, ASN1EncodableVector details)
    {
        this.stepNo = stepNo;
        this.details = new DLSequence(details);
    }

    private TranscriptBlock(ASN1Sequence seq)
    {
        this.stepNo = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().intValue();
        this.details = ASN1Sequence.getInstance(seq.getObjectAt(1));
    }

    public static final TranscriptBlock getInstance(Object o)
    {
        if (o instanceof TranscriptBlock)
        {
            return (TranscriptBlock)o;
        }
        else if (o != null)
        {
            return new TranscriptBlock(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(stepNo));
        v.add(details);

        return new DERSequence(v);
    }

    public int getStepNo()
    {
        return stepNo;
    }

    public ASN1Sequence getDetails()
    {
        return details;
    }

    public int size()
    {
        return details.size();
    }
}