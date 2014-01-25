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
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * Carrier for a fragment of a file.
 */
public class FileTransferMessage
    extends ASN1Object
{
    private final String fileName;
    private final byte[] chunk;

    /**
     * Create a message for a particular file with zero or more bytes of data.
     *
     * @param fileName file name data belongs to.
     * @param chunk the data to be appended.
     */
    public FileTransferMessage(String fileName, byte[] chunk)
    {
        this.fileName = fileName;
        this.chunk = chunk;
    }

    /**
     * Create an END OF TRANSFER message.
     *
     * @param fileName file name to signal end of transfer for.
     */
    public FileTransferMessage(String fileName)
    {
        this.fileName = fileName;
        this.chunk = null;
    }

    private FileTransferMessage(ASN1Sequence sequence)
    {
        this.fileName = DERUTF8String.getInstance(sequence.getObjectAt(0)).getString();
        if (sequence.size() > 1)
        {
            this.chunk = DEROctetString.getInstance(sequence.getObjectAt(1)).getOctets();
        }
        else
        {
            this.chunk = null;
        }
    }

    public static FileTransferMessage getInstance(Object o)
    {
        if (o instanceof FileTransferMessage)
        {
            return (FileTransferMessage)o;
        }
        else if (o != null)
        {
            return new FileTransferMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public String getFileName()
    {
        return fileName;
    }

    public boolean isEndOfTransfer()
    {
        return chunk == null;
    }

    public byte[] getChunk()
    {
        return chunk;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(fileName));

        if (chunk != null)
        {
            v.add(new DEROctetString(chunk));
        }

        return new DERSequence(v);
    }
}
