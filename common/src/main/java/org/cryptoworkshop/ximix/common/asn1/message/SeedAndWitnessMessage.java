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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

/**
 * Request message to fetch a generated seed value.
 */
public class SeedAndWitnessMessage
    extends ASN1Object
{
    private final byte[] seed;
    private final byte[] witness;

    /**
     * Base constructor.
     *
     * @param seed the name of the board the seed is associated with.
     * @param witness the operation number the seed is associated with.
     */
    public SeedAndWitnessMessage(byte[] seed, byte[] witness)
    {
        this.seed = seed;
        this.witness = witness;
    }

    private SeedAndWitnessMessage(ASN1Sequence sequence)
    {
        this.seed = ASN1OctetString.getInstance(sequence.getObjectAt(0)).getOctets();
        this.witness = ASN1OctetString.getInstance(sequence.getObjectAt(1)).getOctets();
    }

    public static final SeedAndWitnessMessage getInstance(Object o)
    {
        if (o instanceof SeedAndWitnessMessage)
        {
            return (SeedAndWitnessMessage)o;
        }
        else if (o != null)
        {
            return new SeedAndWitnessMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DEROctetString(seed));
        v.add(new DEROctetString(witness));

        return new DERSequence(v);
    }

    public byte[] getSeed()
    {
        return seed;
    }

    public byte[] getWitness()
    {
        return witness;
    }
}
