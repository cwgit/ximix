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
        ACTIVATE_BOARD,
        DOWNLOAD_BOARD_CONTENTS,
        MOVE_BOARD_TO_NODE,
        TRANSFER_TO_BOARD,
        TRANSFER_TO_BOARD_ENDED,
        CLEAR_BACKUP_BOARD,
        TRANSFER_TO_BACKUP_BOARD,
        FETCH_BOARD_STATUS,
        SUSPEND_BOARD,
        BOARD_DOWNLOAD_LOCK,
        BOARD_DOWNLOAD_UNLOCK,
        BOARD_SHUFFLE_LOCK,
        BOARD_SHUFFLE_UNLOCK,
        GENERATE_KEY_PAIR,
        STORE_SHARE,
        PARTIAL_DECRYPT,
        SIGNATURE_MESSAGE,
        START_SHUFFLE_AND_MOVE_BOARD_TO_NODE,
        SHUFFLE_AND_MOVE_BOARD_TO_NODE,
        SHUFFLE_AND_RETURN_BOARD,
        INITIATE_INTRANSIT_BOARD,
        NODE_INFO_UPDATE,
        NODE_STATISTICS
    }

    public CommandMessage(Type type, ASN1Encodable payload)
    {
        super(type, payload);
    }

    private CommandMessage(ASN1Sequence seq)
    {
        super(Type.values()[ASN1Enumerated.getInstance(seq.getObjectAt(1)).getValue().intValue()], seq.getObjectAt(2));
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
                throw new IllegalArgumentException("malformed command message");
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
