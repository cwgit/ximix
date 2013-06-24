package org.cryptoworkshop.ximix.common.message;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.math.ec.ECCurve;

public class StoreSecretShareMessage
    extends ASN1Object
{
    private final String keyID;
    private final ASN1Encodable secretShareMessage;

    public StoreSecretShareMessage(String keyID, ASN1Encodable secretShareMessage)
    {
        this.keyID = keyID;
        this.secretShareMessage = secretShareMessage;
    }

    public StoreSecretShareMessage(ASN1Sequence sequence)
    {
        this.keyID = DERUTF8String.getInstance(sequence.getObjectAt(0)).getString();
        this.secretShareMessage = sequence.getObjectAt(1);
    }

    public static final StoreSecretShareMessage getInstance(Object o)
    {
        if (o instanceof StoreSecretShareMessage)
        {
            return (StoreSecretShareMessage)o;
        }
        else if (o != null)
        {
            return new StoreSecretShareMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public String getKeyID()
    {
        return keyID;
    }

    public ASN1Encodable getSecretShareMessage()
    {
        return secretShareMessage;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String(keyID));
        v.add(secretShareMessage);

        return new DERSequence(v);

    }
}
