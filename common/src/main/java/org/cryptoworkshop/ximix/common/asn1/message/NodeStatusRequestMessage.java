package org.cryptoworkshop.ximix.common.asn1.message;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 *
 */
public class NodeStatusRequestMessage
    extends ASN1Object
{
    private Type type = null;


    private NodeStatusRequestMessage(Type type)
    {

        this.type = type;
    }

    public static NodeStatusRequestMessage forFullDetails()
    {
        NodeStatusRequestMessage msg = new NodeStatusRequestMessage(Type.GET_FULL_DETAILS);

        return msg;
    }


    public static NodeStatusRequestMessage forStatisticsRequest()
    {
        NodeStatusRequestMessage msg = new NodeStatusRequestMessage(Type.GET_STATISTICS);

        return msg;
    }



    public static NodeStatusRequestMessage getInstance(Object o)
    {
        if (o instanceof NodeStatusRequestMessage)
        {
            return (NodeStatusRequestMessage)o;
        }
        else if (o instanceof Type)
        {
            return new NodeStatusRequestMessage((Type)o);
        }
        else if (o instanceof ASN1Sequence)
        {
            ASN1Sequence seq = (ASN1Sequence)o;
            ASN1Enumerated eTYpe = (ASN1Enumerated)seq.getObjectAt(0);

            Type type = Type.values()[eTYpe.getValue().intValue()];
            NodeStatusRequestMessage out = new NodeStatusRequestMessage(type);

            return out;
        }

        throw new IllegalArgumentException("Can not convert from " + o.getClass().getName() + " to " + NodeStatusRequestMessage.class.getName() + " instance");
    }

    public Type getType()
    {
        return type;
    }


    @Override
    public ASN1Primitive toASN1Primitive()
    {

        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(new ASN1Enumerated(type.ordinal()));
        return new DERSequence(seq);
    }


    public static enum Type
    {


        SET_PERIOD,


        GET_STATISTICS,

        GET_FULL_DETAILS
    }
}
