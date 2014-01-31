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
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * Response message giving an error message.
 */
public class ErrorMessage
    extends ASN1Object
{
    private final String message;

    /**
     * Base constructor.
     *
     * @param message the error message.
     */
    public ErrorMessage(String message)
    {
        this.message = message;
    }

    private ErrorMessage(DERUTF8String message)
    {
        this.message = message.getString();
    }

    public static final ErrorMessage getInstance(Object o)
    {
        if (o instanceof ErrorMessage)
        {
            return (ErrorMessage)o;
        }
        else if (o != null)
        {
            return new ErrorMessage(DERUTF8String.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(true, 0, new DERUTF8String(message));
    }

    public String getMessage()
    {
        return message;
    }
}
