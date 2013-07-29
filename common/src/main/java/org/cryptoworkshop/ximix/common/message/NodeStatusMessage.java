package org.cryptoworkshop.ximix.common.message;

import org.bouncycastle.asn1.*;

import java.nio.charset.Charset;
import java.util.*;

/**
 *
 */
public class NodeStatusMessage
    extends ASN1Object
{

    private static final Charset UTF8 = Charset.forName("UTF8");
    public static final NodeStatusMessage NULL_MESSAGE;


    private enum ValueType
    {
        STRING, INT, LONG, MAP, LIST
    }


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
        timestamp = ((ASN1Integer)set.getObjectAt(t++)).getValue().longValue();

        for (; t < set.size(); t++)
        {
            ASN1Sequence pair = (ASN1Sequence)set.getObjectAt(t);
            values.put(
                ((DERUTF8String)pair.getObjectAt(0)).getString(),
                asn1TypeToObject((ASN1Sequence)pair.getObjectAt(1))
            );
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

    private Object asn1TypeToObject(ASN1Sequence sequence)
    {
        Object out = null;

        ValueType type = ValueType.values()[((ASN1Enumerated)sequence.getObjectAt(0)).getValue().intValue()];

        switch (type)
        {

            case STRING:
            {
                out = ((DERUTF8String)sequence.getObjectAt(1)).getString();
            }
            break;
            case INT:
            {
                out = ((ASN1Integer)sequence.getObjectAt(1)).getValue().intValue();
            }
            break;
            case LONG:
            {
                out = ((ASN1Integer)sequence.getObjectAt(1)).getValue().longValue();
            }
            break;

            case LIST:
            {
                out = new ArrayList<Object>();
                Enumeration e = ((ASN1Sequence)sequence.getObjectAt(1)).getObjects();
                while (e.hasMoreElements())
                {
                    ((List)out).add(asn1TypeToObject((ASN1Sequence)e.nextElement()));
                }
            }
            break;

            case MAP:
            {
                out = new HashMap();

                Enumeration e = ((ASN1Sequence)sequence.getObjectAt(1)).getObjects();

                while (e.hasMoreElements())
                {
                    ((Map)out).put(asn1TypeToObject((ASN1Sequence)e.nextElement()), asn1TypeToObject((ASN1Sequence)e.nextElement()));
                }

            }
            break;
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

    private ASN1Sequence objToASNType(Object type)
    {
        ASN1EncodableVector out = new ASN1EncodableVector();
        if (type instanceof String)
        {
            out.add(new ASN1Enumerated(ValueType.STRING.ordinal()));
            out.add(new DERUTF8String(((String)type)));
        }
        else if (type instanceof Integer)
        {
            out.add(new ASN1Enumerated(ValueType.INT.ordinal()));
            out.add(new ASN1Integer((Integer)type));
        }
        else if (type instanceof Long)
        {
            out.add(new ASN1Enumerated(ValueType.LONG.ordinal()));
            out.add(new ASN1Integer((Long)type));
        }
        else if (type instanceof List)
        {
            out.add(new ASN1Enumerated(ValueType.LIST.ordinal()));
            ASN1EncodableVector vec = new ASN1EncodableVector();

            for (Object o : (List)type)
            {
                vec.add(objToASNType(o));
            }
            out.add(new DERSequence(vec));
        }
        else if (type instanceof Map)
        {
            out.add(new ASN1Enumerated(ValueType.MAP.ordinal()));
            ASN1EncodableVector vec = new ASN1EncodableVector();

            Iterator it = ((Map)type).entrySet().iterator();
            while (it.hasNext())
            {
                Map.Entry ent = (Map.Entry)it.next();
                vec.add(objToASNType(ent.getKey()));
                vec.add(objToASNType(ent.getValue()));
            }
            out.add(new DERSequence(vec));
        }
        else
        {
            throw new IllegalArgumentException("Unable to encode type: " + type.getClass().getName());
        }
        return new DERSequence(out);
    }

    public boolean isNullStatistics()
    {
        return timestamp == -1;
    }

    public void putValue(String name, Object value)
    {
        values.put(name, value);
    }


}
