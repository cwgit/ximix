package org.cryptoworkshop.ximix.common.test;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.cryptoworkshop.ximix.common.message.NodeStatusMessage;
import org.junit.Test;

/**
 *
 */
public class NodeStatusMessageTest extends TestCase
{

    @Test
    public void testEncodeDecode()
        throws Exception
    {
        long ts = System.currentTimeMillis();

        NodeStatusMessage msg = new NodeStatusMessage();
        msg.setTimestamp(ts);

        msg.getValues().put("a","bar");
        msg.getValues().put("b",10);

        ASN1Primitive prim = msg.toASN1Primitive();

        NodeStatusMessage res = NodeStatusMessage.getInstance(prim);
        TestCase.assertTrue(msg.getValues().get("a").equals(res.getValues().get("a")));
        TestCase.assertTrue(msg.getValues().get("b").equals(res.getValues().get("b")));

    }
}
