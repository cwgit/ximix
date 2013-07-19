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

import java.math.BigInteger;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.Set;
import java.util.TreeSet;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.cryptoworkshop.ximix.common.service.Algorithm;

public class ECKeyGenParams
    extends KeyGenerationParameters
{
    private final String domainParameters;
    private final BigInteger h;
    private final String keyID;
    private final int threshold;
    private final Set<String> nodesToUse;
    private final Algorithm algorithm;


    public ECKeyGenParams(String keyID, Algorithm algorithm, BigInteger h, String domainParameters, int threshold, Set<String> nodesToUse)
    {
        super(EC_REG_CURVE);
        this.keyID = keyID;
        this.algorithm = algorithm;
        this.domainParameters = domainParameters;
        this.h = h;
        this.threshold = threshold;
        this.nodesToUse = nodesToUse;
    }

    ECKeyGenParams(ASN1Sequence seq)
    {
        super(EC_REG_CURVE);
        this.keyID = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
        this.algorithm = Algorithm.values()[ASN1Integer.getInstance(seq.getObjectAt(2)).getValue().intValue()];
        this.domainParameters = DERUTF8String.getInstance(seq.getObjectAt(3)).getString();
        this.h = ASN1Integer.getInstance(seq.getObjectAt(4)).getValue();
        this.threshold = ASN1Integer.getInstance(seq.getObjectAt(5)).getValue().intValue();
        this.nodesToUse = toOrderedSet(ASN1Sequence.getInstance(seq.getObjectAt(6)));
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(EC_REG_CURVE));
        v.add(new DERUTF8String(keyID));
        v.add(new ASN1Integer(algorithm.ordinal()));
        v.add(new DERUTF8String(domainParameters));
        v.add(new ASN1Integer(h));
        v.add(new ASN1Integer(threshold));
        v.add(toASN1Sequence(nodesToUse));

        return new DERSequence(v);
    }

    public String getDomainParameters()
    {
        return domainParameters;
    }

    public String getKeyID()
    {
        return keyID;
    }

    public BigInteger getH()
    {
        return h;
    }

    private static Set<String> toOrderedSet(ASN1Sequence set)
    {
        Set<String> orderedSet = new TreeSet(new CaseInsensitiveComparator());

        for (Enumeration en = set.getObjects(); en.hasMoreElements();)
        {
            orderedSet.add(DERUTF8String.getInstance(en.nextElement()).getString());
        }

        return Collections.unmodifiableSet(orderedSet);
    }

    private static ASN1Sequence toASN1Sequence(Set<String> set)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (String name : set)
        {
            v.add(new DERUTF8String(name));
        }

        return new DERSequence(v);
    }

    public Set<String> getNodesToUse()
    {
        return nodesToUse;
    }

    public int getThreshold()
    {
        return threshold;
    }

    public Algorithm getAlgorithm()
    {
        return algorithm;
    }

    private static class CaseInsensitiveComparator
        implements Comparator<String>
    {
        @Override
        public int compare(String s1, String s2)
        {
            return s1.compareToIgnoreCase(s2);
        }
    }
}
