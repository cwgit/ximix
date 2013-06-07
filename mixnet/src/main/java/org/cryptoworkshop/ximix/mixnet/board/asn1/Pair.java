package org.cryptoworkshop.ximix.mixnet.board.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECCurve;

public class Pair
    extends ASN1Object
{
    private final ECPair ecPair;
    private ECPair pair;

    public Pair(ECPair ecPair)
    {
        this.ecPair = ecPair;
    }

    /**
     * <pre>
     *     Pair ::= SEQUENCE {
     *         x OCTET STRING,
     *         y OCTET STRING
     *     }
     * </pre>
     *
     * @return an encoding of an ASN.1 sequence
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DEROctetString(ecPair.getX().getEncoded()));
        v.add(new DEROctetString(ecPair.getY().getEncoded()));

        return new DERSequence(v);
    }

    public static Pair getInstance(ECCurve curve, Object o)
    {
        if (o instanceof Pair)
        {
            return (Pair)o;
        }
        if (o != null)
        {
            ASN1Sequence s = ASN1Sequence.getInstance(o);

            byte[] encX = ASN1OctetString.getInstance(s.getObjectAt(0)).getOctets();
            byte[] encY = ASN1OctetString.getInstance(s.getObjectAt(1)).getOctets();

            return new Pair(new ECPair(curve.decodePoint(encX), curve.decodePoint(encY)));
        }

        return null;
    }

    public ECPair getECPair()
    {
        return ecPair;
    }
}
