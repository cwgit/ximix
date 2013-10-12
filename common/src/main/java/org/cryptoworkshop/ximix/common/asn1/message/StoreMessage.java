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
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * Carrier message to associate an ID with a share.
 */
public class StoreMessage
    extends ASN1Object
{
    private final String id;
    private final ASN1Encodable secretShareMessage;

    /**
     * Base constructor.
     *
     * @param id the ID to store the share against.
     * @param secretShareMessage the share details.
     */
    public StoreMessage(String id, ASN1Encodable secretShareMessage)
    {
        this.id = id;
        this.secretShareMessage = secretShareMessage;
    }

    private StoreMessage(ASN1Sequence sequence)
    {
        this.id = DERUTF8String.getInstance(sequence.getObjectAt(0)).getString();
        this.secretShareMessage = sequence.getObjectAt(1);
    }

    public static final StoreMessage getInstance(Object o)
    {
        if (o instanceof StoreMessage)
        {
            return (StoreMessage)o;
        }
        else if (o != null)
        {
            return new StoreMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public String getID()
    {
        return id;
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
        v.add(secretShareMessage);

        return new DERSequence(v);

    }
}
