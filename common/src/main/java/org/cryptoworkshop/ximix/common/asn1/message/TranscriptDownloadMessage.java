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
import org.cryptoworkshop.ximix.common.util.TranscriptType;

/**
 * Request message for a transcript download.
 */
public class TranscriptDownloadMessage
    extends ASN1Object
{
    private final long queryID;
    private final long operationNumber;
    private final int stepNo;
    private final TranscriptType type;
    private final int maxNumberOfMessages;

    /**
     * Base constructor.
     *
     * @param queryID  the ID of the query this transcript download is associated with.
     * @param operationNumber the operation number the transcript download is for.
     * @param stepNo the number of the step in the operation the transcript download is for.
     * @param type  the type of transcript requested.
     * @param maxNumberOfMessages the maximum number of messages that can be accepted in a response.
     */
    public TranscriptDownloadMessage(long queryID, long operationNumber, int stepNo, TranscriptType type, int maxNumberOfMessages)
    {
        this.queryID = queryID;
        this.operationNumber = operationNumber;
        this.stepNo = stepNo;
        this.type = type;
        this.maxNumberOfMessages = maxNumberOfMessages;
    }

    private TranscriptDownloadMessage(ASN1Sequence seq)
    {
        this.queryID = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().longValue();
        this.operationNumber = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue().longValue();
        this.stepNo = ASN1Integer.getInstance(seq.getObjectAt(2)).getValue().intValue();
        this.type = TranscriptType.values()[ASN1Integer.getInstance(seq.getObjectAt(3)).getValue().intValue()];
        this.maxNumberOfMessages = ASN1Integer.getInstance(seq.getObjectAt(4)).getValue().intValue();
    }

    public static final TranscriptDownloadMessage getInstance(Object o)
    {
        if (o instanceof TranscriptDownloadMessage)
        {
            return (TranscriptDownloadMessage)o;
        }
        else if (o != null)
        {
            return new TranscriptDownloadMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(queryID));
        v.add(new ASN1Integer(operationNumber));
        v.add(new ASN1Integer(stepNo));
        v.add(new ASN1Integer(type.ordinal()));
        v.add(new ASN1Integer(maxNumberOfMessages));

        return new DERSequence(v);
    }

    public long getOperationNumber()
    {
        return operationNumber;
    }

    public int getMaxNumberOfMessages()
    {
        return maxNumberOfMessages;
    }

    public int getStepNo()
    {
        return stepNo;
    }

    public TranscriptType getType()
    {
        return type;
    }

    public long getQueryID()
    {
        return queryID;
    }
}
