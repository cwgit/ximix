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
import org.bouncycastle.asn1.DERUTF8String;

/**
 * Carrier message for the upload of single message at a particular index.
 */
public class BoardUploadIndexedMessage
    extends ASN1Object
{
    private final String boardName;
    private final int index;
    private final byte[][] data;

    /**
     * Base constructor.
     *
     * @param boardName the name of board the message is destined for.
     * @param index the index number of the message.
     * @param data the message data.
     */
    public BoardUploadIndexedMessage(String boardName, int index, byte[] data)
    {
        this(boardName, index, new byte[][] { data });
    }

    /**
     * Block constructor.
     *
     * @param boardName the name of board the messages are destined for.
     * @param startIndex the start index for the message block.
     * @param data an array of the message data.
     */
    public BoardUploadIndexedMessage(String boardName, int startIndex, byte[][] data)
    {
        this.boardName = boardName;
        this.index = startIndex;
        this.data = data.clone();
    }

    private BoardUploadIndexedMessage(ASN1Sequence seq)
    {
        this.boardName = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
        this.index = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue().intValue();

        ASN1Sequence dataBlock = ASN1Sequence.getInstance(seq.getObjectAt(2));

        this.data = new byte[dataBlock.size()][];

        for (int i = 0; i != dataBlock.size(); i++)
        {
            data[i] = ASN1OctetString.getInstance(dataBlock.getObjectAt(i)).getOctets();
        }
    }

    public static final BoardUploadIndexedMessage getInstance(Object o)
    {
        if (o instanceof BoardUploadMessage)
        {
            return (BoardUploadIndexedMessage)o;
        }
        else if (o != null)
        {
            return new BoardUploadIndexedMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(boardName));
        v.add(new ASN1Integer(index));

        ASN1EncodableVector dataV = new ASN1EncodableVector();

        for (int i = 0; i != data.length; i++)
        {
            dataV.add(new DEROctetString(data[i]));
        }

        v.add(new DERSequence(dataV));

        return new DERSequence(v);
    }

    public String getBoardName()
    {
        return boardName;
    }

    /**
     * Return the index of the first message in the data block.
     *
     * @return a message index value for the first message.
     */
    public int getIndex()
    {
        return index;
    }

    public byte[][] getData()
    {
        return data;
    }
}
