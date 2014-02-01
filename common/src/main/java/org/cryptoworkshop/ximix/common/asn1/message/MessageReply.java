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
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * Basic reply message.
 */
public class MessageReply
    extends ASN1Object
{
    private final Type type;
    private final ASN1Encodable payload;

    public static enum Type
    {
        OKAY,
        ERROR,
        /**
         * Sent when a node is receiving messages but is in the process of a graceful shutdown.
         */
        EXITING
    }

    /**
     * Basic constructor.
     *
     * @param type the type associated with reply.
     */
    public MessageReply(Type type)
    {
        this(type, null);
    }

    /**
     * Payload constructor.
     *
     * @param type the type of the reply.
     * @param payload some additional payload information to be interpreted by the receiver.
     */
    public MessageReply(Type type, ASN1Encodable payload)
    {
        this.type = type;
        this.payload = payload;
    }

    private MessageReply(ASN1Sequence seq)
    {
        this.type = Type.values()[ASN1Enumerated.getInstance(seq.getObjectAt(0)).getValue().intValue()];

        if (seq.size() > 1)
        {
            this.payload = seq.getObjectAt(1);
        }
        else
        {
            this.payload = null;
        }
    }

    public static final MessageReply getInstance(Object o)
    {
        if (o instanceof MessageReply)
        {
            return (MessageReply)o;
        }
        else if (o != null)
        {
            return new MessageReply(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public Type getType()
    {
        return type;
    }

    public ASN1Encodable getPayload()
    {
        return payload;
    }

    /**
     * Interpret the payload to create an error string.
     *
     * @return a String representation of the payload.
     */
    public String interpretPayloadAsError()
    {
        if (payload instanceof DERUTF8String)
        {
            return DERUTF8String.getInstance(payload).getString();
        }

        if (payload instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(payload);

            if (taggedObject.getTagNo() == 0)
            {
                return DERUTF8String.getInstance(taggedObject, true).getString();
            }
            if (taggedObject.getTagNo() == 1)
            {
                BoardErrorStatusMessage statusMessage = BoardErrorStatusMessage.getInstance(ASN1Sequence.getInstance(taggedObject, true));

                return statusMessage.getBoardName() + ": " + statusMessage.getStatus();
            }
        }

        return "Unknown error object";
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Enumerated(type.ordinal()));

        if (payload != null)
        {
            v.add(payload);
        }

        return new DERSequence(v);
    }
}
