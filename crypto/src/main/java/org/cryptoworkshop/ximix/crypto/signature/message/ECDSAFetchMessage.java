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
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

public class ECDSAFetchMessage
    extends ASN1Object
{
    private final String sigID;
    private final String keyID;
    private final Set<String> nodesToUse;

    public ECDSAFetchMessage(String sigID, String keyID, Set<String> nodesToUse)
    {
        this.sigID = sigID;
        this.keyID = keyID;
        this.nodesToUse = MessageUtils.toOrderedSet(nodesToUse);
    }

    private ECDSAFetchMessage(ASN1Sequence seq)
    {
        this.sigID = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
        this.keyID = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
        this.nodesToUse = MessageUtils.toOrderedSet(ASN1Sequence.getInstance(seq.getObjectAt(2)));
    }

    public static final ECDSAFetchMessage getInstance(Object o)
    {
        if (o instanceof ECDSAFetchMessage)
        {
            return (ECDSAFetchMessage)o;
        }
        else if (o != null)
        {
            return new ECDSAFetchMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(sigID));
        v.add(new DERUTF8String(keyID));
        v.add(MessageUtils.toASN1Sequence(nodesToUse));

        return new DERSequence(v);
    }

    public String getSigID()
    {
        return sigID;
    }

    public Set<String> getNodesToUse()
    {
        return nodesToUse;
    }

    public String getKeyID()
    {
        return keyID;
    }
}
