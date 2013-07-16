package org.cryptoworkshop.ximix.common.message;

import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSet;

class MessageUtils
{
    static ASN1Set toASN1Set(Set<String> set)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (String name : set)
        {
            v.add(new DERUTF8String(name));
        }

        return new DLSet(v);
    }
}
