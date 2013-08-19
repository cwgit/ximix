package org.cryptoworkshop.ximix.common.asn1.message;

import java.lang.reflect.InvocationTargetException;
import java.nio.charset.Charset;
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
 *
 */
public class NodeStatusMessage
    extends ASN1Object
{
    private static final Charset UTF8 = Charset.forName("UTF8");
    private final int hash;
    private final Map<String, Object> values;


    public NodeStatusMessage(int hash)
    {
        this(new HashMap<String, Object>(), hash);
    }

    public NodeStatusMessage(Map<String, Object> source, int hash)
    {
        Map<String, Object> tmp = new HashMap<>();
        tmp.putAll(source);
        values = Collections.unmodifiableMap(tmp);
        this.hash = hash;
    }


    private NodeStatusMessage(ASN1Sequence seq)
    {
        int t = 0;

        hash = ((ASN1Integer)seq.getObjectAt(t++)).getValue().intValue();
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

    public static NodeStatusMessage getInstance(Object o)
    {

        if (o instanceof NodeStatusMessage)
        {
            return (NodeStatusMessage)o;
        }
        else if (o != null)
        {
            return new NodeStatusMessage(ASN1Sequence.getInstance(o));
        }

        return null;
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
        out.add(new ASN1Integer(hash));
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
        private final int hash;
        private final Class<T> type;
        private final HashMap<String, Object> values = new HashMap<>();
        private final Class[] params = new Class[]{Map.class, int.class};

        public Builder(int hash, Class<T> type)
        {
            this.hash = hash;
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
                return type.getConstructor(params).newInstance(values, hash);
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
    public static class StatisticsMessage
        extends NodeStatusMessage
    {

        public StatisticsMessage(int hash)
        {
            super(hash);
        }

        public StatisticsMessage(Map<String, Object> source, int hash)
        {
            super(source, hash);
        }

        public StatisticsMessage(ASN1Sequence seq)
        {
            super(seq);
        }

        public static StatisticsMessage getInstance(Object o)
        {

            if (o instanceof StatisticsMessage)
            {
                return (StatisticsMessage)o;
            }
            else if (o != null)
            {
                return new StatisticsMessage(ASN1Sequence.getInstance(o));
            }

            return null;
        }

    }

    /**
     * Info message.
     */
    public static class InfoMessage
        extends NodeStatusMessage
    {
        public InfoMessage(int hash)
        {
            super(hash);
        }

        public InfoMessage(Map<String, Object> source, int hash)
        {
            super(source, hash);
        }

        public InfoMessage(ASN1Sequence seq)
        {
            super(seq);
        }

        public static InfoMessage getInstance(Object o)
        {

            if (o instanceof InfoMessage)
            {
                return (InfoMessage)o;
            }
            else if (o != null)
            {
                return new InfoMessage(ASN1Sequence.getInstance(o));
            }

            return null;
        }

    }

}
