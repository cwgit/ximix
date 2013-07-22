package org.cryptoworkshop.ximix.common.message;

import org.bouncycastle.asn1.*;

/**
 *
 */
public class HealthInfoCommandMessage extends ASN1Object
{
    private Type type = null;
    private Integer period = null;

    private HealthInfoCommandMessage(Type type)
    {

        this.type = type;
    }

    public HealthInfoCommandMessage(Type type, int period)
    {
        this.type = type;
        this.period = period;
    }

    public static HealthInfoCommandMessage getInstance(Object o)
    {
        if (o instanceof HealthInfoCommandMessage)
        {
            return (HealthInfoCommandMessage)o;
        }
        else if (o instanceof Type)
        {
            return new HealthInfoCommandMessage((Type)o);
        }
        else if (o instanceof ASN1Sequence)
        {
            ASN1Sequence seq = (ASN1Sequence)o;
            ASN1Enumerated eTYpe = (ASN1Enumerated)seq.getObjectAt(0);
            return new HealthInfoCommandMessage(Type.values()[eTYpe.getValue().intValue()], ((ASN1Integer)seq.getObjectAt(1)).getValue().intValue());
        }

        throw new IllegalArgumentException("Can not convert from "+o.getClass().getName()+" to "+HealthInfoCommandMessage.class.getName()+" instance");
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
        if (type == Type.SET_PERIOD)
        {
            seq.add(new ASN1Integer(period));
        }
        return new DERSequence(seq);
    }



    public static enum Type
    {

        RESET,


        SET_PERIOD,


        GET_STATIC_INFO,


        GET_STATISTICS
    }
}
