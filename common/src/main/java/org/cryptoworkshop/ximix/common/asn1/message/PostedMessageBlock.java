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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * Carrier class for a block of PostedMessage objects.
 */
public class PostedMessageBlock
    extends ASN1Object
{
    private final List<PostedMessage> messages;

    public static class Builder
    {
        private final List<PostedMessage> messages;
        private final int capacity;

        public Builder(int capacity)
        {
            this.capacity = capacity;
            this.messages = new ArrayList<>(capacity);
        }

        public Builder add(int index, byte[] message)
        {
            messages.add(new PostedMessage(index, message));

            return this;
        }

        public Builder add(int index, byte[] message, byte[] commitment)
        {
            messages.add(new PostedMessage(index, message, commitment));

            return this;
        }

        public Builder clear()
        {
            messages.clear();

            return this;
        }

        public PostedMessageBlock build()
        {
            return new PostedMessageBlock(Collections.unmodifiableList(messages));
        }

        public int capacity()
        {
            return capacity;
        }

        public boolean isFull()
        {
            return messages.size() == capacity;
        }

        public boolean isEmpty()
        {
            return messages.isEmpty();
        }
    }

    private PostedMessageBlock(List<PostedMessage> messages)
    {
        this.messages = messages;
    }

    private PostedMessageBlock(ASN1Sequence seq)
    {
        messages = new ArrayList<>(seq.size());

        for (Enumeration en = seq.getObjects(); en.hasMoreElements();)
        {
            this.messages.add(PostedMessage.getInstance(en.nextElement()));
        }
    }

    public static final PostedMessageBlock getInstance(Object o)
    {
        if (o instanceof PostedMessageBlock)
        {
            return (PostedMessageBlock)o;
        }
        else if (o != null)
        {
            return new PostedMessageBlock(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (PostedMessage message : messages)
        {
            v.add(message);
        }

        return new DERSequence(v);
    }

    public boolean hasCommitments()
    {
        return !messages.isEmpty() && messages.get(0).hasCommitment();
    }

    public List<PostedMessage> getMessages()
    {
        return messages;
    }

    public int size()
    {
        return messages.size();
    }
}
