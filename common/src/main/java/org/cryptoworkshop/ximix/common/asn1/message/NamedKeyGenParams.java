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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;

/**
 * Carrier class for key generation parameters using a named parameter set.
 */
public class NamedKeyGenParams
    extends KeyGenerationParameters
{
    private final String domainParameters;
    private final BigInteger h;
    private final String keyID;
    private final int threshold;
    private final List<String> nodesToUse;
    private final Algorithm algorithm;

    /**
     * Base constructor.
     *
     * @param keyID ID of the key to be generated.
     * @param algorithm algorithm the key is to be generated for.
     * @param h the h value for the splitting algorithm.
     * @param domainParameters identifier for the domain parameters to use.
     * @param threshold the minimum threshold for simple private key operations.
     * @param nodesToUse the names of the nodes to take part in the sharing process.
     * @deprecated this is only here due to issues with JPBC, once we can deal with BLS key generation properly this constructor should be removed.
     */
    public NamedKeyGenParams(String keyID, Algorithm algorithm, BigInteger h, String domainParameters, int threshold, List<String> nodesToUse)
    {
        super(NAMED_PARAMETER_SET);
        this.keyID = keyID;
        this.algorithm = algorithm;
        this.domainParameters = domainParameters;
        this.h = h;
        this.threshold = threshold;
        this.nodesToUse = nodesToUse;
    }

    /**
     * Base constructor.
     *
     * @param keyID ID of the key to be generated.
     * @param algorithm algorithm the key is to be generated for.
     * @param domainParameters identifier for the domain parameters to use.
     * @param threshold the minimum threshold for simple private key operations.
     * @param nodesToUse the names of the nodes to take part in the sharing process.
     */
    public NamedKeyGenParams(String keyID, Algorithm algorithm, String domainParameters, int threshold, List<String> nodesToUse)
    {
        super(NAMED_PARAMETER_SET);
        this.keyID = keyID;
        this.algorithm = algorithm;
        this.domainParameters = domainParameters;
        this.h = BigInteger.ZERO;
        this.threshold = threshold;
        this.nodesToUse = nodesToUse;
    }

    NamedKeyGenParams(ASN1Sequence seq)
    {
        super(NAMED_PARAMETER_SET);
        this.keyID = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
        this.algorithm = Algorithm.values()[ASN1Integer.getInstance(seq.getObjectAt(2)).getValue().intValue()];
        this.domainParameters = DERUTF8String.getInstance(seq.getObjectAt(3)).getString();
        this.h = ASN1Integer.getInstance(seq.getObjectAt(4)).getValue();
        this.threshold = ASN1Integer.getInstance(seq.getObjectAt(5)).getValue().intValue();
        this.nodesToUse = toList(ASN1Sequence.getInstance(seq.getObjectAt(6)));
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(NAMED_PARAMETER_SET));
        v.add(new DERUTF8String(keyID));
        v.add(new ASN1Integer(algorithm.ordinal()));
        v.add(new DERUTF8String(domainParameters));
        v.add(new ASN1Integer(h));
        v.add(new ASN1Integer(threshold));
        v.add(toASN1Sequence(nodesToUse));

        return new DERSequence(v);
    }

    /**
     * Return the name of the domain parameters for this set.
     *
     * @return name for domain parameters for generated key.
     */
    public String getDomainParameters()
    {
        return domainParameters;
    }

    /**
     * Return the ID of the key to be generated.
     *
     * @return ID of the key.
     */
    public String getKeyID()
    {
        return keyID;
    }

    /**
     * @deprecated to be removed.
     */
    public BigInteger getH()
    {
        return h;
    }

    private static List<String> toList(ASN1Sequence set)
    {
        List<String> orderedSet = new ArrayList();

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

        return new DERSequence(v);
    }

    /**
     * Return the list of nodes to be used in the generation process.
     *
     * @return list of nodes to use.
     */
    public List<String> getNodesToUse()
    {
        return nodesToUse;
    }

    /**
     * Return the threshold setting for the number of nodes required for private key operations.
     *
     * @return the threshold number for key sharing.
     */
    public int getThreshold()
    {
        return threshold;
    }

    /**
     * Return the algorithm to generate the key for.
     *
     * @return the resulting key's algorithm,
     */
    public Algorithm getAlgorithm()
    {
        return algorithm;
    }
}
