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
 * Carrier message for details of transforms associated with a particular bulletin board.
 */
public class BoardDetailMessage
    extends ASN1Object
{
    private final String boardName;
    private final String host;
    private final int messageCount;
    private final String backupHost;

    /**
     * Base constructor.
     *
     * @param boardName the name of the board this message relates to.
     * @param host the node hosting the board.
     * @param messageCount count of the number of messages on the board.
     * @param backupHost name of the backupHost, null if there isn't one.
     */
    public BoardDetailMessage(String boardName, String host, int messageCount, String backupHost)
    {
        this.boardName = boardName;
        this.host = host;
        this.messageCount = messageCount;
        this.backupHost = backupHost;
    }

    private BoardDetailMessage(ASN1Sequence seq)
    {
        this.boardName = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
        this.host = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
        messageCount = ASN1Integer.getInstance(seq.getObjectAt(2)).getValue().intValue();

        if (seq.size() > 3)
        {
            this.backupHost = DERUTF8String.getInstance(seq.getObjectAt(3)).getString();
        }
        else
        {
            this.backupHost = null;
        }
    }

    public static final BoardDetailMessage getInstance(Object o)
    {
        if (o instanceof BoardDetailMessage)
        {
            return (BoardDetailMessage)o;
        }
        else if (o != null)
        {
            return new BoardDetailMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(boardName));
        v.add(new DERUTF8String(host));
        v.add(new ASN1Integer(messageCount));

        if (backupHost != null)
        {
            v.add(new DERUTF8String(backupHost));
        }

        return new DERSequence(v);
    }

    public String getHost()
    {
        return host;
    }

    public String getBoardName()
    {
        return boardName;
    }

    public int getMessageCount()
    {
        return messageCount;
    }

    public String getBackupHost()
    {
        return backupHost;
    }
}
