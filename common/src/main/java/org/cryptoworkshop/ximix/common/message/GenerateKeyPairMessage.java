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

public class GenerateKeyPairMessage
    extends ASN1Object
{
    private final Set<String> nodesToUse;
    private final String keyID;
    private final int threshold;
    private final BigInteger h;

    public GenerateKeyPairMessage(String keyID, Set<String> nodesToUse, int threshold, BigInteger h)
    {
        // TODO: just in case order is important,,, trying to avoid this if possible.
        Set<String> orderedSet = new TreeSet(new CaseInsensitiveComparator());
        orderedSet.addAll(nodesToUse);

        this.nodesToUse = Collections.unmodifiableSet(orderedSet);
        this.keyID = keyID;
        this.threshold = threshold;
        this.h = h;
    }

    private GenerateKeyPairMessage(ASN1Sequence seq)
    {
        this.nodesToUse = toOrderedSet(ASN1Set.getInstance(seq.getObjectAt(0)));
        this.keyID = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
        this.threshold = ASN1Integer.getInstance(seq.getObjectAt(2)).getValue().intValue();
        this.h = ASN1Integer.getInstance(seq.getObjectAt(3)).getValue();
    }

    public static final GenerateKeyPairMessage getInstance(Object o)
    {
        if (o instanceof GenerateKeyPairMessage)
        {
            return (GenerateKeyPairMessage)o;
        }
        else if (o != null)
        {
            return new GenerateKeyPairMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(toASN1Set(nodesToUse));
        v.add(new DERUTF8String(keyID));
        v.add(new ASN1Integer(threshold));
        v.add(new ASN1Integer(h));

        return new DERSequence(v);
    }

    public String getKeyID()
    {
        return keyID;
    }

    public Set<String> getNodesToUse()
    {
        return nodesToUse;
    }

    public int getThreshold()
    {
        return threshold;
    }

    public BigInteger getH()
    {
        return h;
    }

    private static Set<String> toOrderedSet(ASN1Set set)
    {
        Set<String> orderedSet = new TreeSet(new CaseInsensitiveComparator());

        for (Enumeration en = set.getObjects(); en.hasMoreElements();)
        {
            orderedSet.add(DERUTF8String.getInstance(en.nextElement()).getString());
        }

        return Collections.unmodifiableSet(orderedSet);
    }

    private static ASN1Set toASN1Set(Set<String> set)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (String name : set)
        {
            v.add(new DERUTF8String(name));
        }

        return new DLSet(v);
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
