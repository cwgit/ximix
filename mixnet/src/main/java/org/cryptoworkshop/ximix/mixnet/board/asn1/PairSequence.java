package org.cryptoworkshop.ximix.mixnet.board.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.math.ec.ECCurve;

public class PairSequence
    extends ASN1Object
{
    private final ECPair[] ecPairs;

    public PairSequence(ECPair ecPair)
    {
        this.ecPairs = new ECPair[] { ecPair };
    }

    public PairSequence(ECPair[] ecPairs)
    {
        this.ecPairs = ecPairs.clone();
    }

    private PairSequence(ECCurve curve, ASN1Sequence s)
    {
        ecPairs = new ECPair[s.size()];

        for (int i = 0; i != ecPairs.length; i++)
        {
            ecPairs[i] = Pair.getInstance(curve, s.getObjectAt(i)).getECPair();
        }
    }

    /**
     * <pre>
     *     PairSequence ::= SEQUENCE OF Pair
     * </pre>
     *
     * @return an encoding of an ASN.1 sequence
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (ECPair pair : ecPairs)
        {
            v.add(new Pair(pair));
        }

        return new DERSequence(v);
    }

    public static PairSequence getInstance(ECCurve curve, Object o)
    {
        if (o instanceof PairSequence)
        {
            return (PairSequence)o;
        }
        if (o != null)
        {
            return new PairSequence(curve, ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ECPair[] getECPairs()
    {
        return ecPairs;
    }
}
