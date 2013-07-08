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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

public class StoreSecretShareMessage
    extends ASN1Object
{
    private final String id;
    private final ASN1Encodable secretShareMessage;
    private final int sequenceNo;

    public StoreSecretShareMessage(String id, int sequenceNo, ASN1Encodable secretShareMessage)
    {
        this.id = id;
        this.sequenceNo = sequenceNo;
        this.secretShareMessage = secretShareMessage;
    }

    public StoreSecretShareMessage(ASN1Sequence sequence)
    {
        this.id = DERUTF8String.getInstance(sequence.getObjectAt(0)).getString();
        this.sequenceNo = ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue().intValue();
        this.secretShareMessage = sequence.getObjectAt(2);
    }

    public static final StoreSecretShareMessage getInstance(Object o)
    {
        if (o instanceof StoreSecretShareMessage)
        {
            return (StoreSecretShareMessage)o;
        }
        else if (o != null)
        {
            return new StoreSecretShareMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public String getID()
    {
        return id;
    }

    public int getSequenceNo()
    {
        return sequenceNo;
    }

    public ASN1Encodable getSecretShareMessage()
    {
        return secretShareMessage;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(id));
        v.add(new ASN1Integer(sequenceNo));
        v.add(secretShareMessage);

        return new DERSequence(v);

    }
}
