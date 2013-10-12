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
 * Carrier message for a board creation request.
 */
public class CreateBoardMessage
    extends ASN1Object
{
    private final String boardName;
    private final String backUpHost;

    /**
     * Base constructor.
     *
     * @param boardName the name of the board to create.
     * @param backUpHost the backup host for the board, null if not required.
     */
    public CreateBoardMessage(String boardName, String backUpHost)
    {
        this.boardName = boardName;
        this.backUpHost = backUpHost;
    }

    private CreateBoardMessage(ASN1Sequence seq)
    {
        this.boardName = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
        if (seq.size() == 2)
        {
            this.backUpHost = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
        }
        else
        {
            this.backUpHost = null;
        }
    }

    public static final CreateBoardMessage getInstance(Object o)
    {
        if (o instanceof CreateBoardMessage)
        {
            return (CreateBoardMessage)o;
        }
        else if (o != null)
        {
            return new CreateBoardMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(boardName));

        if (backUpHost != null)
        {
            v.add(new DERUTF8String(backUpHost));
        }

        return new DERSequence(v);
    }

    public String getBoardName()
    {
        return boardName;
    }

    public String getBackUpHost()
    {
        return backUpHost;
    }
}
