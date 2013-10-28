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

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * Carrier message for a general string ID.
 */
public class IDMessage
    extends ASN1Object
{
    private String id;
    private byte[] hash;

    /**
     * Base constructor.
     *
     * @param id the ID of the key being referred to.
     */
    public IDMessage(String id)
    {
        this.id = id;
    }

    private IDMessage(DERUTF8String id)
    {
        this.id = id.getString();
    }

    public static final IDMessage getInstance(Object o)
    {
        if (o instanceof IDMessage)
        {
            return (IDMessage)o;
        }
        else if (o != null)
        {
            return new IDMessage(DERUTF8String.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERUTF8String(id);
    }

    public String getID()
    {
        return id;
    }
}
