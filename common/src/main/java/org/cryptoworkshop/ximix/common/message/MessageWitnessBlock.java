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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class MessageWitnessBlock
    extends ASN1Object
{
    private final List<MessageWitness> witnesses;

    public static class Builder
    {
        private final List<MessageWitness> witnesses;
        private final int capacity;

        public Builder(int capacity)
        {
            this.capacity = capacity;
            this.witnesses = new ArrayList<>(capacity);
        }

        public Builder add(int index, MessageCommitment witness)
        {
            witnesses.add(new MessageWitness(index, witness));

            return this;
        }

        public Builder clear()
        {
            witnesses.clear();

            return this;
        }

        public MessageWitnessBlock build()
        {
            return new MessageWitnessBlock(Collections.unmodifiableList(witnesses));
        }

        public int capacity()
        {
            return capacity;
        }

        public boolean isFull()
        {
            return witnesses.size() == capacity;
        }

        public boolean isEmpty()
        {
            return witnesses.isEmpty();
        }
    }

    private MessageWitnessBlock(List<MessageWitness> witnesses)
    {
        this.witnesses = witnesses;
    }

    private MessageWitnessBlock(ASN1Sequence seq)
    {
        witnesses = new ArrayList<>(seq.size());

        for (Enumeration en = seq.getObjects(); en.hasMoreElements();)
        {
            this.witnesses.add(MessageWitness.getInstance(en.nextElement()));
        }
    }

    public static final MessageWitnessBlock getInstance(Object o)
    {
        if (o instanceof MessageWitnessBlock)
        {
            return (MessageWitnessBlock)o;
        }
        else if (o != null)
        {
            return new MessageWitnessBlock(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (MessageWitness message : witnesses)
        {
            v.add(message);
        }

        return new DERSequence(v);
    }

    public List<MessageWitness> getWitnesses()
    {
        return witnesses;
    }

    public int size()
    {
        return witnesses.size();
    }
}
