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

import java.math.BigInteger;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.Set;
import java.util.TreeSet;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSet;

public class ECKeyGenParams
    extends KeyGenerationParameters
{
    private final String domainParameters;
    private final BigInteger h;

    public ECKeyGenParams(BigInteger h, String domainParameters)
    {
        super(EC_REG_CURVE);
        this.domainParameters = domainParameters;
        this.h = h;
    }

    ECKeyGenParams(ASN1Sequence seq)
    {
        super(EC_REG_CURVE);
        this.domainParameters = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
        this.h = ASN1Integer.getInstance(seq.getObjectAt(2)).getValue();
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(EC_REG_CURVE));
        v.add(new DERUTF8String(domainParameters));
        v.add(new ASN1Integer(h));

        return new DERSequence(v);
    }

    public String getDomainParameters()
    {
        return domainParameters;
    }

    public BigInteger getH()
    {
        return h;
    }
}
