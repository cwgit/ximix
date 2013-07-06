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
package org.cryptoworkshop.ximix.crypto.signature.message;

import java.math.BigInteger;
import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

public class ECDSAInitialiseMessage
    extends ASN1Object
{
    private final String keyID;
    private final Set<String> nodesToUse;
    private final int threshold;
    private final BigInteger n;
    private final String sigID;

    public ECDSAInitialiseMessage(String sigID, String keyID, int threshold, BigInteger n, Set<String> nodesToUse)
    {
        this.sigID = sigID;
        this.nodesToUse = MessageUtils.toOrderedSet(nodesToUse);
        this.threshold = threshold;
        this.n = n;
        this.keyID = keyID;
    }

    private ECDSAInitialiseMessage(ASN1Sequence seq)
    {
        this.sigID = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
        this.keyID = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
        this.threshold = ASN1Integer.getInstance(seq.getObjectAt(2)).getValue().intValue();
        this.n = ASN1Integer.getInstance(seq.getObjectAt(3)).getValue();
        this.nodesToUse = MessageUtils.toOrderedSet(ASN1Sequence.getInstance(seq.getObjectAt(4)));
    }

    public static final ECDSAInitialiseMessage getInstance(Object o)
    {
        if (o instanceof ECDSAInitialiseMessage)
        {
            return (ECDSAInitialiseMessage)o;
        }
        else if (o != null)
        {
            return new ECDSAInitialiseMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(sigID));
        v.add(new DERUTF8String(keyID));
        v.add(new ASN1Integer(threshold));
        v.add(new ASN1Integer(n));
        v.add(MessageUtils.toASN1Sequence(nodesToUse));

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

    public BigInteger getN()
    {
        return n;
    }

    public String getSigID()
    {
        return sigID;
    }
}
