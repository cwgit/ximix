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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.cryptoworkshop.ximix.common.service.Algorithm;

public class KeyGenerationMessage
    extends ASN1Object
{
    private final Algorithm algorithm;
    private final List<String> nodesToUse;
    private final String keyID;
    private final int threshold;
    private final KeyGenParams keyGenParameters;

    public KeyGenerationMessage(Algorithm algorithm, String keyID, KeyGenParams keyGenParameters, int threshold, String... nodesToUse)
    {
        this(algorithm, keyID, keyGenParameters, threshold, Arrays.asList((String[])nodesToUse));
    }

    public KeyGenerationMessage(Algorithm algorithm, String keyID, KeyGenParams keyGenParameters, int threshold, List<String> nodesToUse)
    {
        this.algorithm = algorithm;
        this.nodesToUse = Collections.unmodifiableList(nodesToUse);
        this.keyID = keyID;
        this.threshold = threshold;
        this.keyGenParameters = keyGenParameters;
    }

    private KeyGenerationMessage(ASN1Sequence seq)
    {
        this.algorithm = Algorithm.values()[ASN1Enumerated.getInstance(seq.getObjectAt(0)).getValue().intValue()];
        this.keyID = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
        this.keyGenParameters = KeyGenParams.getInstance(seq.getObjectAt(2));
        this.threshold = ASN1Integer.getInstance(seq.getObjectAt(3)).getValue().intValue();
        this.nodesToUse = toList(ASN1Sequence.getInstance(seq.getObjectAt(4)));
    }

    public static final KeyGenerationMessage getInstance(Object o)
    {
        if (o instanceof KeyGenerationMessage)
        {
            return (KeyGenerationMessage)o;
        }
        else if (o != null)
        {
            return new KeyGenerationMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Enumerated(algorithm.ordinal()));
        v.add(new DERUTF8String(keyID));
        v.add(keyGenParameters);
        v.add(new ASN1Integer(threshold));
        v.add(toASN1Sequence(nodesToUse));      // TODO: should be sequence?

        return new DERSequence(v);
    }

    public String getKeyID()
    {
        return keyID;
    }

    public List<String> getNodesToUse()
    {
        return nodesToUse;
    }

    public int getThreshold()
    {
        return threshold;
    }

    public KeyGenParams getKeyGenParameters()
    {
        return keyGenParameters;
    }

    private static List<String> toList(ASN1Sequence set)
    {
        List<String> orderedSet = new ArrayList<>(set.size());

        for (Enumeration en = set.getObjects(); en.hasMoreElements();)
        {
            orderedSet.add(DERUTF8String.getInstance(en.nextElement()).getString());
        }

        return Collections.unmodifiableList(orderedSet);
    }

    private static ASN1Sequence toASN1Sequence(List<String> set)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (String name : set)
        {
            v.add(new DERUTF8String(name));
        }

        return new DLSequence(v);
    }

    public Algorithm getAlgorithm()
    {
        return algorithm;
    }
}
