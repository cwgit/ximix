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
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

public class TranscriptQueryResponse
    extends ASN1Object
{
    private final long queryID;
    private final String boardName;
    private final int[] stepNos;

    public TranscriptQueryResponse(long queryID, String boardName, int[] stepNos)
    {
        this.queryID = queryID;
        this.boardName = boardName;
        this.stepNos = stepNos;
    }

    private TranscriptQueryResponse(ASN1Sequence seq)
    {
        this.queryID = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().longValue();
        this.boardName = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();

        ASN1Sequence steps = ASN1Sequence.getInstance(seq.getObjectAt(2));

        stepNos = new int[steps.size()];

        for (int i = 0; i != stepNos.length; i++)
        {
            stepNos[i] = ASN1Integer.getInstance(steps.getObjectAt(i)).getValue().intValue();
        }
    }

    public static final TranscriptQueryResponse getInstance(Object o)
    {
        if (o instanceof TranscriptQueryResponse)
        {
            return (TranscriptQueryResponse)o;
        }
        else if (o != null)
        {
            return new TranscriptQueryResponse(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(queryID));
        v.add(new DERUTF8String(boardName));

        ASN1EncodableVector stepV = new ASN1EncodableVector();
        for (int i = 0; i != stepNos.length; i++)
        {
            stepV.add(new ASN1Integer(stepNos[i]));
        }

        v.add(new DERSequence(stepV));

        return new DERSequence(v);
    }

    public long getQueryID()
    {
        return queryID;
    }

    public int[] stepNos()
    {
        return stepNos.clone();
    }

    public String getBoardName()
    {
        return boardName;
    }
}
