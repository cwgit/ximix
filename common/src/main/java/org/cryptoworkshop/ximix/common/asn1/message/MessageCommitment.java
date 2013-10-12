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
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

/**
 * Carrier message for a message commitment secrets and transformation details.
 */
public class MessageCommitment
    extends ASN1Object
{
    private final byte[] detail;
    private final int newIndex;
    private final byte[] secret;

    private MessageCommitment(ASN1Sequence seq)
    {
        this.newIndex = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().intValue();
        this.secret = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();

        if (seq.size() > 2)
        {
            this.detail = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
        }
        else
        {
            this.detail = null;
        }
    }

    /**
     * Constructor for a secret only commitment message.
     *
     * @param newIndex the index of the shuffled message the secret relates to.
     * @param secret the secret related to the commitment.
     */
    public MessageCommitment(int newIndex, byte[] secret)
    {
        this.detail = null;
        this.newIndex = newIndex;
        this.secret = secret;
    }

    /**
     * Constructor for a commitment message containing both the commitment message and the detail associated with transformation
     * of the message the commitment is based on.
     *
     * @param newIndex the index of the shuffled message the secret and detail relate to.
     * @param secret the secret related to the commitment.
     * @param detail data related to the committed message - usually the random value mixed in.
     */
    public MessageCommitment(int newIndex, byte[] secret, byte[] detail)
    {
        this.detail = detail.clone();
        this.newIndex = newIndex;
        this.secret = secret;
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

        v.add(new ASN1Integer(newIndex));
        v.add(new DEROctetString(secret));

        if (detail != null)
        {
            v.add(new DEROctetString(detail));
        }

        return new DERSequence(v);
    }

    public byte[] getSecret()
    {
        return secret;
    }

    public byte[] getDetail()
    {
        if (detail != null)
        {
            return detail.clone();
        }

        return null;
    }

    public int getNewIndex()
    {
        return newIndex;
    }
}
