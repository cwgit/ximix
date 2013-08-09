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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.Commitment;

public class MessageCommitment
    extends ASN1Object
{
    private final byte[] commitment;
    private final byte[] secret;

    private MessageCommitment(ASN1Sequence seq)
    {
        this.commitment = ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets();
        this.secret = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
    }

    public MessageCommitment(Commitment witness)
    {
        this.commitment = witness.getCommitment();
        this.secret = witness.getSecret();
    }

    public static final MessageCommitment getInstance(Object o)
    {
        if (o instanceof MessageCommitment)
        {
            return (MessageCommitment)o;
        }
        else if (o != null)
        {
            return new MessageCommitment(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DEROctetString(commitment));
        v.add(new DEROctetString(secret));

        return new DERSequence(v);
    }

    public Commitment getCommitment()
    {
        return new Commitment(secret, commitment);
    }
}
