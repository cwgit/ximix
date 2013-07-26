package org.cryptoworkshop.ximix.common.test;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.cryptoworkshop.ximix.common.message.NodeStatusMessage;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public class NodeStatusMessageTest
    extends TestCase
{

    @Test
    public void testEncodeDecode()
        throws Exception
    {
        long ts = System.currentTimeMillis();

        List<String> testList = new ArrayList<>();
        testList.add("cats");
        testList.add("dogs");
        testList.add("fish");
        testList.add("rabbit");


        NodeStatusMessage msg = new NodeStatusMessage();
        msg.setTimestamp(ts);

        msg.getValues().put("a", "bar");
        msg.getValues().put("b", 10);
        msg.putValue("list",testList);




        ASN1Primitive prim = msg.toASN1Primitive();

       // System.out.println(ASN1Dump.dumpAsString(prim, true));


        NodeStatusMessage res = NodeStatusMessage.getInstance(prim);
        TestCase.assertTrue(msg.getValues().get("a").equals(res.getValues().get("a")));
        TestCase.assertTrue(msg.getValues().get("b").equals(res.getValues().get("b")));

        int t=0;
        for (String v : testList)
        {
            TestCase.assertEquals(v, ((List)res.getValues().get("list")).get(t++));
        }

    }
}
