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

/**
 * Command message for initiating signature creation.
 */
public class SignatureCreateMessage
    extends ASN1Object
{
    private final String keyID;
    private final byte[] message;
    private final Set<String> nodesToUse;
    private final int threshold;

    /**
     * Base constructor.
     *
     * @param keyID the ID of the key to use to create the signature.
     * @param message the message to be signed.
     * @param threshold the threshold required to create the signature.
     * @param nodesToUse the names of the nodes that can be used in the process.
     */
    public SignatureCreateMessage(String keyID, byte[] message, int threshold, String... nodesToUse)
    {
        this.nodesToUse = MessageUtils.toOrderedSet(nodesToUse);
        this.threshold = threshold;
        this.keyID = keyID;
        this.message = message;
    }

    private SignatureCreateMessage(ASN1Sequence seq)
    {
        this.keyID = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
        this.threshold = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue().intValue();
        this.message = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
        this.nodesToUse = MessageUtils.toOrderedSet(ASN1Sequence.getInstance(seq.getObjectAt(3)));
    }

    public static final SignatureCreateMessage getInstance(Object o)
    {
        if (o instanceof SignatureCreateMessage)
        {
            return (SignatureCreateMessage)o;
        }
        else if (o != null)
        {
            return new SignatureCreateMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(keyID));
        v.add(new ASN1Integer(threshold));
        v.add(new DEROctetString(message));
        v.add(MessageUtils.toASN1Sequence(nodesToUse));

        return new DERSequence(v);
    }

    public String getKeyID()
    {
        return keyID;
    }

    public byte[] getMessage()
    {
        return message;
    }

    public Set<String> getNodesToUse()
    {
        return nodesToUse;
    }

    public int getThreshold()
    {
        return threshold;
    }
}
