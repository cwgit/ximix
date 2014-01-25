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

/**
 * Carrier message to request decryption of a shuffled board. Arrival of this message implies all the board data,
 * including the transcripts, has been uploaded.
 */
public class DecryptShuffledBoardMessage
    extends ASN1Object
{
    private final String boardName;
    private final String keyID;

    /**
     * Base constructor.
     *
     * @param keyID the ID of the private key to decrypt against.
     * @param boardName the source board that the original shuffle was on.
     */
    public DecryptShuffledBoardMessage(String keyID, String boardName)
    {
        this.keyID = keyID;
        this.boardName = boardName;
    }

    private DecryptShuffledBoardMessage(ASN1Sequence seq)
    {
        this.keyID = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
        this.boardName= DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
    }

    public static final DecryptShuffledBoardMessage getInstance(Object o)
    {
        if (o instanceof DecryptShuffledBoardMessage)
        {
            return (DecryptShuffledBoardMessage)o;
        }
        else if (o != null)
        {
            return new DecryptShuffledBoardMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(keyID));
        v.add(new DERUTF8String(boardName));

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
}
