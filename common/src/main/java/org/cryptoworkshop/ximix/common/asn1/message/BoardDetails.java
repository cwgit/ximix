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

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

public class BoardDetails
    extends ASN1Object
{
    private final String boardName;
    private final Set<String> transformNames;

    public BoardDetails(String boardName, Set<String> transformNames)
    {
        this.boardName = boardName;
        this.transformNames = Collections.unmodifiableSet(new HashSet<String>(transformNames));
    }

    private BoardDetails(ASN1Sequence seq)
    {
        this.boardName = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();

        ASN1Set asn1Trans = ASN1Set.getInstance(seq.getObjectAt(1));
        Set<String>  sTrans = new HashSet<String>();

        for (Enumeration en = asn1Trans.getObjects(); en.hasMoreElements();)
        {
            sTrans.add(DERUTF8String.getInstance(en.nextElement()).getString());
        }

        transformNames = Collections.unmodifiableSet(sTrans);
    }

    public static final BoardDetails getInstance(Object o)
    {
        if (o instanceof BoardDetails)
        {
            return (BoardDetails)o;
        }
        else if (o != null)
        {
            return new BoardDetails(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(boardName));
        v.add(MessageUtils.toASN1Set(transformNames));

        return new DERSequence(v);
    }

    public String getBoardName()
    {
        return boardName;
    }

    public Set<String> getTransformNames()
    {
        return transformNames;
    }
}
