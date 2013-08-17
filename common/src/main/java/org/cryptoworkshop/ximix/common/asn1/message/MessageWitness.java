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

public class MessageWitness
    extends ASN1Object
{
    private final int    index;
    private final MessageCommitment witness;

    private MessageWitness(ASN1Sequence seq)
    {
        this.index = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().intValue();
        this.witness = MessageCommitment.getInstance(seq.getObjectAt(1));
    }

    public MessageWitness(int index, MessageCommitment witness)
    {
        this.index = index;
        this.witness = witness;
    }

    public static final MessageWitness getInstance(Object o)
    {
        if (o instanceof MessageWitness)
        {
            return (MessageWitness)o;
        }
        else if (o != null)
        {
            return new MessageWitness(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(index));
        v.add(witness);

        return new DERSequence(v);
    }

    public int getIndex()
    {
        return index;
    }

    public MessageCommitment getWitness()
    {
        return witness;
    }
}
