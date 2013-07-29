package org.cryptoworkshop.ximix.common.message;

import org.bouncycastle.asn1.*;

/**
 *
 */
public class NodeStatusRequestMessage
    extends ASN1Object
{
    private Type type = null;
    private Integer period = null;
    private Integer toCount = null;

    private NodeStatusRequestMessage(Type type)
    {

        this.type = type;
    }

    public static NodeStatusRequestMessage forFullDetails()
    {
        NodeStatusRequestMessage msg = new NodeStatusRequestMessage(Type.GET_FULL_DETAILS);

        return msg;
    }

    public static NodeStatusRequestMessage forPeriodChange(int period)
    {
        NodeStatusRequestMessage msg = new NodeStatusRequestMessage(Type.SET_PERIOD);
        msg.period = period;
        return msg;
    }

    public static NodeStatusRequestMessage forTrim(int count)
    {
        NodeStatusRequestMessage msg = new NodeStatusRequestMessage(Type.TRIM);
        msg.toCount = count;
        return msg;
    }

    public static NodeStatusRequestMessage forStatisticsRequest(int count)
    {
        NodeStatusRequestMessage msg = new NodeStatusRequestMessage(Type.GET_STATISTICS);
        msg.toCount = count;
        return msg;
    }

    public static ASN1Encodable forStaticInfo()
    {
        NodeStatusRequestMessage msg = new NodeStatusRequestMessage(Type.GET_INFO);
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
            switch (type)
            {
                case TRIM:
                    out.toCount = ((ASN1Integer)seq.getObjectAt(1)).getValue().intValue();
                    break;

                case SET_PERIOD:
                    out.period = ((ASN1Integer)seq.getObjectAt(1)).getValue().intValue();
                    break;
            }

            return out;
        }

        throw new IllegalArgumentException("Can not convert from " + o.getClass().getName() + " to " + NodeStatusRequestMessage.class.getName() + " instance");
    }

    public Type getType()
    {
        return type;
    }

    public Integer getPeriod()
    {
        return period;
    }

    public Integer getToCount()
    {
        return toCount;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {

        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(new ASN1Enumerated(type.ordinal()));
        if (type == Type.SET_PERIOD)
        {
            seq.add(new ASN1Integer(period));
        }
        else if (type == Type.TRIM)
        {
            seq.add(new ASN1Integer(toCount));
        }


        return new DERSequence(seq);
    }


    public static enum Type
    {
        TRIM,

        SET_PERIOD,

        GET_INFO,

        GET_STATISTICS,

        GET_FULL_DETAILS
    }
}
