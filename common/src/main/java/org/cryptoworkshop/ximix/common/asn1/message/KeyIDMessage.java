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

public class KeyIDMessage
    extends ASN1Object
{
    private String keyID;
    private byte[] hash;

    public KeyIDMessage(String keyID)
    {
        this.keyID = keyID;
    }

    private KeyIDMessage(DERUTF8String keyID)
    {
        this.keyID = keyID.getString();
    }

    public static final KeyIDMessage getInstance(Object o)
    {
        if (o instanceof KeyIDMessage)
        {
            return (KeyIDMessage)o;
        }
        else if (o != null)
        {
            return new KeyIDMessage(DERUTF8String.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERUTF8String(keyID);
    }

    public String getKeyID()
    {
        return keyID;
    }
}
