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

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * General carrier for a BigInteger value.
 */
public class BigIntegerMessage
    extends ASN1Object
{
    private final BigInteger value;

    public BigIntegerMessage(BigInteger value)
    {
        this.value = value;
    }

    private BigIntegerMessage(ASN1Integer integer)
    {
        this.value = integer.getValue();
    }

    public static final BigIntegerMessage getInstance(Object o)
    {
        if (o instanceof BigIntegerMessage)
        {
            return (BigIntegerMessage)o;
        }
        else if (o != null)
        {
            return new BigIntegerMessage(ASN1Integer.getInstance(o));
        }

        return null;
    }

    /**
     * <pre>
     * INTEGER value.
     * </pre>
     * @return
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new ASN1Integer(value);
    }

    public BigInteger getValue()
    {
        return value;
    }
}
