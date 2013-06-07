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
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class CommandMessage
    extends Message<CommandMessage.Type>
{
    public static enum Type
        implements MessageType
    {
        MOVE_BOARD_TO_NODE,
        SHUFFLE_AND_MOVE_BOARD_TO_NODE
    }

    public CommandMessage(Type type, ASN1Encodable payload)
    {
        super(type, payload);
    }

    private CommandMessage(ASN1Sequence seq)
    {
        super(Type.values()[ASN1Enumerated.getInstance(seq.getObjectAt(0)).getValue().intValue()], seq.getObjectAt(1));
    }

    public static final CommandMessage getInstance(Object o)
    {
        if (o instanceof CommandMessage)
        {
            return (CommandMessage)o;
        }
        else if (o != null)
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(o);

            if (!seq.getObjectAt(0).equals(COMMAND_LEVEL))
            {
                throw new IllegalArgumentException("malformed client message");
            }

            return new CommandMessage(seq);
        }

        return null;
    }

    public Type getType()
    {
        return type;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(COMMAND_LEVEL);
        v.add(new ASN1Enumerated(type.ordinal()));
        v.add(payload);

        return new DERSequence(v);
    }
}
