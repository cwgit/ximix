package org.cryptoworkshop.ximix.common.asn1.message;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * Carrier class for (name, value) pairs associated with a node's status/stats
 */
public class NodeStatusMessage
    extends ASN1Object
{
    private final Map<String, Object> values;

    protected NodeStatusMessage(Map<String, Object> source)
    {
        Map<String, Object> tmp = new HashMap<>();
        tmp.putAll(source);
        values = Collections.unmodifiableMap(tmp);
    }

    private NodeStatusMessage(ASN1Sequence seq)
    {
        int t = 0;

        values = new HashMap<>();
        for (; t < seq.size(); t++)
        {
            ASN1Sequence pair = (ASN1Sequence)seq.getObjectAt(t);
            values.put(
                ((DERUTF8String)pair.getObjectAt(0)).getString(),
                asn1TypeToObject((ASN1Sequence)pair.getObjectAt(1))
            );
        }
    }

    public Map<String, Object> getValues()
    {
        return values;
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

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector out = new ASN1EncodableVector();
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

    private enum ValueType
    {
        STRING, INT, LONG, MAP, LIST
    }

    public static class Builder<T extends NodeStatusMessage>
    {
        private final Class<T> type;
        private final HashMap<String, Object> values = new HashMap<>();
        private final Class[] params = new Class[]{Map.class};

        public Builder(Class<T> type)
        {
            this.type = type;
        }

        public void putAll(Map<String, Object> newValues)
        {
            values.putAll(newValues);
        }

        public void put(String name, Object value)
        {
            values.put(name, value);
        }

        public void put(String key, String name, Object value)
        {
            Map<String, Object> m = (Map<String, Object>)values.get(key);
            if (m == null)
            {
                m = new HashMap<>();
                values.put(key, m);
            }

            m.put(name, value);
        }


        public T build()
        {
            try
            {
                return type.getConstructor(params).newInstance(values);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("Unable to build " + type);
            }

        }

    }

    /**
     * Statistics message.
     */
    public static class Statistics
        extends NodeStatusMessage
    {
        public Statistics(Map<String, Object> source)
        {
            super(source);
        }

        private Statistics(ASN1Sequence seq)
        {
            super(seq);
        }

        public static Statistics getInstance(Object o)
        {

            if (o instanceof Statistics)
            {
                return (Statistics)o;
            }
            else if (o != null)
            {
                return new Statistics(ASN1Sequence.getInstance(o));
            }

            return null;
        }

    }

    /**
     * Info message.
     */
    public static class Info
        extends NodeStatusMessage
    {
        public Info(Map<String, Object> source)
        {
            super(source);
        }

        public Info(ASN1Sequence seq)
        {
            super(seq);
        }

        public static Info getInstance(Object o)
        {

            if (o instanceof Info)
            {
                return (Info)o;
            }
            else if (o != null)
            {
                return new Info(ASN1Sequence.getInstance(o));
            }

            return null;
        }

    }

}
