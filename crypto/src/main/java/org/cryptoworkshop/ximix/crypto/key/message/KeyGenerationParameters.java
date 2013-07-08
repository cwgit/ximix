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
package org.cryptoworkshop.ximix.crypto.key.message;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;

public abstract class KeyGenerationParameters
    extends ASN1Object
{
    public static final int EC_REG_CURVE = 0;

    private final int type;

    protected KeyGenerationParameters(int type)
    {
        this.type = type;
    }

    public static final KeyGenerationParameters getInstance(Object o)
    {
        if (o instanceof KeyGenerationParameters)
        {
            return (KeyGenerationParameters)o;
        }
        else if (o != null)
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(o);

            if (ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().intValue() == EC_REG_CURVE)
            {
                return new ECKeyGenParams(seq);
            }
        }

        return null;
    }

    public int getType()
    {
        return type;
    }
}
