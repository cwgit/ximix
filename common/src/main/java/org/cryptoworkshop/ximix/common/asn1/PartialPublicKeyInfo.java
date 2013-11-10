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
package org.cryptoworkshop.ximix.common.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 * Partial public key descriptor.
 */
public class PartialPublicKeyInfo
    extends ASN1Object
{
    private final int sequenceNo;
    private final SubjectPublicKeyInfo partialKeyInfo;

    /**
     * Base constructor.
     *
     * @param sequenceNo the sequence number for the partial key in the threshold generation.
     * @param partialKeyInfo SubjectPublicKeyInfo representing the partial public key for this sequence number.
     */
    public PartialPublicKeyInfo(int sequenceNo, SubjectPublicKeyInfo partialKeyInfo)
    {
        this.sequenceNo = sequenceNo;
        this.partialKeyInfo = partialKeyInfo;
    }

    private PartialPublicKeyInfo(ASN1Sequence seq)
    {
        this.sequenceNo = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().intValue();
        this.partialKeyInfo = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(1));
    }

    public static final PartialPublicKeyInfo getInstance(Object o)
    {
        if (o instanceof PartialPublicKeyInfo)
        {
            return (PartialPublicKeyInfo)o;
        }
        else if (o != null)
        {
            return new PartialPublicKeyInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(sequenceNo));
        v.add(partialKeyInfo);

        return new DERSequence(v);
    }

    public SubjectPublicKeyInfo getPartialKeyInfo()
    {
        return partialKeyInfo;
    }

    public int getSequenceNo()
    {
        return sequenceNo;
    }
}
