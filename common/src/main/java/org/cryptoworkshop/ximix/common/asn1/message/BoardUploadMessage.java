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
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * Carrier message client upload of one or more messages to the end of a board.
 */
public class BoardUploadMessage
    extends ASN1Object
{
    private final String boardName;
    private final byte[][] data;

    /**
     * Base constructor.
     *
     * @param boardName the name of board the message is destined for.
     * @param data the message data.
     */
    public BoardUploadMessage(String boardName, byte[] data)
    {
        this(boardName, new byte[][] { data });
    }

    /**
     * Block constructor.
     *
     * @param boardName the name of board the messages are destined for.
     * @param data an array of the message data.
     */
    public BoardUploadMessage(String boardName, byte[][] data)
    {
        this.boardName = boardName;
        this.data = data.clone();
    }

    private BoardUploadMessage(ASN1Sequence seq)
    {
        this.boardName = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();

        ASN1Sequence dataBlock = ASN1Sequence.getInstance(seq.getObjectAt(1));

        this.data = new byte[dataBlock.size()][];

        for (int i = 0; i != dataBlock.size(); i++)
        {
            data[i] = ASN1OctetString.getInstance(dataBlock.getObjectAt(i)).getOctets();
        }
    }

    public static final BoardUploadMessage getInstance(Object o)
    {
        if (o instanceof BoardUploadMessage)
        {
            return (BoardUploadMessage)o;
        }
        else if (o != null)
        {
            return new BoardUploadMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(boardName));

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

    public byte[][] getData()
    {
        return data;
    }
}
