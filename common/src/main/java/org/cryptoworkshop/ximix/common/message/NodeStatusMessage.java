package org.cryptoworkshop.ximix.common.message;

import org.bouncycastle.asn1.*;

import java.nio.charset.Charset;
import java.util.*;

/**
 *
 */
public class NodeStatusMessage extends ASN1Object
{

    private static final Charset UTF8 = Charset.forName("UTF8");
    public static final NodeStatusMessage NULL_MESSAGE;

    static
    {
        NULL_MESSAGE = new NodeStatusMessage();
        NULL_MESSAGE.timestamp = -1;
    }

    private long timestamp = -1;
    private Map<String, Object> values = new HashMap<>();
    private boolean nullStatistics = false;

    public NodeStatusMessage()
    {

    }


    private NodeStatusMessage(Map<String, Object> source)
    {
        values.putAll(source);
    }

    private NodeStatusMessage(ASN1Sequence set)
    {

        int t = 0;
        timestamp = ((ASN1Integer)set.getObjectAt(t++)).getValue().intValue();

        for (; t < set.size(); t++)
        {
            ASN1Sequence pair = (ASN1Sequence)set.getObjectAt(t);
            values.put((String)duckType(pair.getObjectAt(0)), duckType(pair.getObjectAt(1)));
        }

    }

    public static NodeStatusMessage getInstance(Object o)
    {

        if (o instanceof ASN1Sequence)
        {
            return new NodeStatusMessage((ASN1Sequence)o);
        }


        return getInstance(o, null);
    }

    public static NodeStatusMessage getInstance(Object o, Long timestamp)
    {


        if (o instanceof HashMap)
        {
            return new NodeStatusMessage((Map)o).withTimeStamp(timestamp);
        }
        else if (o instanceof NodeStatusMessage)
        {
            return new NodeStatusMessage(((NodeStatusMessage)o).values).withTimeStamp(timestamp);
        }

        throw new IllegalArgumentException("Unsupported object type, " + o.getClass().getName());
    }

    public long getTimestamp()
    {
        return timestamp;
    }

    public void setTimestamp(long timestamp)
    {
        this.timestamp = timestamp;
    }

    public Map<String, Object> getValues()
    {
        return values;
    }

    public void setValues(Map<String, Object> values)
    {
        this.values = values;
    }

    private Object duckType(Object asnType)
    {
        Object out = null;

        if (asnType instanceof DERUTF8String)
        {
            out = ((DERUTF8String)asnType).getString();
        }
        else if (asnType instanceof ASN1Integer)
        {
            out = ((ASN1Integer)asnType).getValue().intValue();
        }
        else if (asnType instanceof ASN1Sequence)
        {
            out = new ArrayList<Object>();
            Enumeration e = ((ASN1Sequence)asnType).getObjects();
            while (e.hasMoreElements())
            {
                ((List)out).add(duckType(e.nextElement()));
            }
        }


        return out;
    }

    private NodeStatusMessage withTimeStamp(Long timestamp)
    {
        if (timestamp != null)
        {
            this.timestamp = timestamp.longValue();
        }
        return this;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {

        ASN1EncodableVector out = new ASN1EncodableVector();
        out.add(new ASN1Integer(timestamp));
        Iterator<Map.Entry<String, Object>> it = values.entrySet().iterator();

        while (it.hasNext())
        {
            ASN1EncodableVector pair = new ASN1EncodableVector();
            Map.Entry<String, Object> entry = it.next();

            pair.add(new DERUTF8String(entry.getKey()));

            pair.add(objToASNType(entry.getValue()));
            out.add(new DERSequence(pair));
        }


        return new DERSequence(out);
    }

    private ASN1Object objToASNType(Object type)
    {
        if (type instanceof String)
        {
            return new DERUTF8String(((String)type));
        }
        else if (type instanceof Integer)
        {
            return new ASN1Integer((Integer)type);
        }
        else if (type instanceof List)
        {
            ASN1EncodableVector vec = new ASN1EncodableVector();

            for (Object o : (List)type)
            {
                vec.add(objToASNType(o));
            }
            return new DERSequence(vec);
        }

        throw new IllegalArgumentException("Unable to encode type: " + type.getClass().getName());

    }

    public boolean isNullStatistics()
    {
        return timestamp == -1;
    }
}
