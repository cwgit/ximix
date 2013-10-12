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
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * Base class for top level message carriers.
 *
 * @param <T> the enumeration related to the types of messages that can be carried.
 */
public abstract class Message<T extends Enum<T>>
    extends ASN1Object
{
    protected static final ASN1Integer COMMAND_LEVEL = new ASN1Integer(1);
    protected static final ASN1Integer CLIENT_LEVEL = new ASN1Integer(2);

    protected final T type;
    protected final ASN1Encodable payload;

    /**
     * Base constructor.
     *
     * @param type the type of payload.
     * @param payload the payload data.
     */
    public Message(T type, ASN1Encodable payload)
    {
        this.type = type;
        this.payload = payload;
    }

    public static Message getInstance(Object o)
    {
        if (o instanceof Message)
        {
            return (Message)o;
        }
        else if (o != null)
        {
            ASN1Sequence s = ASN1Sequence.getInstance(o);

            if (s.getObjectAt(0).equals(COMMAND_LEVEL))
            {
                return CommandMessage.getInstance(s);
            }
            else
            {
                return ClientMessage.getInstance(s);
            }
        }

        return null;
    }

    public ASN1Encodable getPayload()
    {
        return payload;
    }

    public abstract T getType();
}
