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
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.cryptoworkshop.ximix.common.service.Algorithm;

public class AlgorithmServiceMessage
    extends ASN1Object
{
    private final Algorithm algorithm;
    private final ASN1Encodable payload;

    public AlgorithmServiceMessage(Algorithm algorithm, ASN1Encodable payload)
    {
        this.algorithm = algorithm;
        this.payload = payload;
    }

    private AlgorithmServiceMessage(ASN1Sequence seq)
    {
        this.algorithm = Algorithm.values()[ASN1Enumerated.getInstance(seq.getObjectAt(0)).getValue().intValue()];
        this.payload = seq.getObjectAt(1);
    }

    public static AlgorithmServiceMessage getInstance(Object o)
    {
        if (o instanceof AlgorithmServiceMessage)
        {
            return (AlgorithmServiceMessage)o;
        }
        else if (o != null)
        {
            return new AlgorithmServiceMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Enumerated(algorithm.ordinal()));
        v.add(payload);

        return new DERSequence(v);
    }

    public Algorithm getAlgorithm()
    {
        return algorithm;
    }

    public ASN1Encodable getPayload()
    {
        return payload;
    }
}
