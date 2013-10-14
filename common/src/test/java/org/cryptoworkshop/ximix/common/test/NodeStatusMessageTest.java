package org.cryptoworkshop.ximix.common.test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.cryptoworkshop.ximix.common.asn1.message.NodeStatusMessage;
import org.junit.Test;

/**
 * Test for a node status message.
 */
public class NodeStatusMessageTest
    extends TestCase
{

    @Test
    public void testEncodeDecode()
        throws Exception
    {

        List<String> testList = new ArrayList<>();
        testList.add("cats");
        testList.add("dogs");
        testList.add("fish");
        testList.add("rabbit");


        NodeStatusMessage.Builder<NodeStatusMessage.Info> builder = new NodeStatusMessage.Builder(NodeStatusMessage.Info.class);


        builder.put("a", "bar");
        builder.put("b", 10);
        builder.put("list", testList);


        Map m = new HashMap<>();

        m.put("foo", "bar");
        m.put("cat", 1);


        builder.put("map", m);

        NodeStatusMessage nsm = builder.build();


        ASN1Primitive prim = nsm.toASN1Primitive();

        System.out.println(ASN1Dump.dumpAsString(prim, true));


        NodeStatusMessage res = NodeStatusMessage.Info.getInstance(prim);
        TestCase.assertTrue(nsm.getValues().get("a").equals(res.getValues().get("a")));
        TestCase.assertTrue(nsm.getValues().get("b").equals(res.getValues().get("b")));

        int t = 0;
        for (String v : testList)
        {
            TestCase.assertEquals(v, ((List)res.getValues().get("list")).get(t++));
        }

    }
}
