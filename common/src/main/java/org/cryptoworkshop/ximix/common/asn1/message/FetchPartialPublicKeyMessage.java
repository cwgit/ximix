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
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

public class FetchPartialPublicKeyMessage
    extends ASN1Object
{
    private final String nodeID;
    private final String keyID;

    public FetchPartialPublicKeyMessage(String nodeID, String keyID)
    {
        this.nodeID = nodeID;
        this.keyID = keyID;
    }

    private FetchPartialPublicKeyMessage(ASN1Sequence seq)
    {
        this.nodeID = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
        this.keyID = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
    }

    public static final FetchPartialPublicKeyMessage getInstance(Object o)
    {
        if (o instanceof FetchPartialPublicKeyMessage)
        {
            return (FetchPartialPublicKeyMessage)o;
        }
        else if (o != null)
        {
            return new FetchPartialPublicKeyMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(nodeID));
        v.add(new DERUTF8String(keyID));

        return new DERSequence(v);
    }

    public String getNodeID()
    {
        return nodeID;
    }

    public String getKeyID()
    {
        return keyID;
    }
}
