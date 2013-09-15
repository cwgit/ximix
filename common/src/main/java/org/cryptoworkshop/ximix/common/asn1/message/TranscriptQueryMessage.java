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

public class TranscriptQueryMessage
    extends ASN1Object
{
    private final long operationNumber;

    public TranscriptQueryMessage(long operationNumber)
    {
        this.operationNumber = operationNumber;
    }

    private TranscriptQueryMessage(ASN1Sequence seq)
    {
        this.operationNumber = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().longValue();
    }

    public static final TranscriptQueryMessage getInstance(Object o)
    {
        if (o instanceof TranscriptQueryMessage)
        {
            return (TranscriptQueryMessage)o;
        }
        else if (o != null)
        {
            return new TranscriptQueryMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(operationNumber));

        return new DERSequence(v);
    }

    public long getOperationNumber()
    {
        return operationNumber;
    }
}
