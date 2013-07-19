package org.cryptoworkshop.ximix.common.message;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.cryptoworkshop.ximix.common.service.Algorithm;

public class SignatureMessage
    extends ASN1Object
{
    private final Algorithm algorithm;
    private final Enum type;
    private final ASN1Encodable payload;

    public SignatureMessage(Algorithm algorithm, Enum type, ASN1Encodable payload)
    {
        this.algorithm = algorithm;
        this.type = type;
        this.payload = payload;
    }

    public static final SignatureMessage getInstance(Enum[] types, Object o)
    {
        if (o instanceof SignatureMessage)
        {
            return (SignatureMessage)o;
        }
        else if (o != null)
        {
            return new SignatureMessage(types, ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private SignatureMessage(Enum[] types, ASN1Sequence seq)
    {
        this.algorithm = Algorithm.values()[ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().intValue()];
        this.type = types[ASN1Enumerated.getInstance(seq.getObjectAt(1)).getValue().intValue()];
        this.payload = seq.getObjectAt(2);
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(algorithm.ordinal()));
        v.add(new ASN1Enumerated(type.ordinal()));
        v.add(payload);

        return new DERSequence(v);
    }

    public Enum getType()
    {
        return type;
    }

    public ASN1Encodable getPayload()
    {
        return payload;
    }
}
