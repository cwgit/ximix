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

/**
 * Request message to download a chunk of partially-decrypted board data.
 */
public class DownloadShuffledBoardMessage
    extends ASN1Object
{
    private final String boardName;
    private final String keyID;
    private final int    blockSize;

    /**
     * Base constructor.
     *
     * @param keyID the ID of the private key to decrypt against.
     * @param boardName the source board that the original shuffle was on.
     * @param blockSize number of messages to return at a time.
     */
    public DownloadShuffledBoardMessage(String keyID, String boardName, int blockSize)
    {
        this.keyID = keyID;
        this.boardName = boardName;
        this.blockSize = blockSize;
    }

    private DownloadShuffledBoardMessage(ASN1Sequence seq)
    {
        this.keyID = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
        this.boardName= DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
        this.blockSize = ASN1Integer.getInstance(seq.getObjectAt(2)).getValue().intValue();
    }

    public static final DownloadShuffledBoardMessage getInstance(Object o)
    {
        if (o instanceof DownloadShuffledBoardMessage)
        {
            return (DownloadShuffledBoardMessage)o;
        }
        else if (o != null)
        {
            return new DownloadShuffledBoardMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(keyID));
        v.add(new DERUTF8String(boardName));
        v.add(new ASN1Integer(blockSize));

        return new DERSequence(v);
    }

    public String getBoardName()
    {
        return boardName;
    }

    public String getKeyID()
    {
        return keyID;
    }

    public int getBlockSize()
    {
        return blockSize;
    }
}
