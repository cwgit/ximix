package org.cryptoworkshop.ximix.test.tests;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROutputStream;
import org.cryptoworkshop.ximix.common.message.CommandMessage;
import org.cryptoworkshop.ximix.common.message.PermuteAndMoveMessage;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

/**
 * Basic testing concerning messaging.
 */
public class MessageTest extends TestCase
{

    @Test
    public void testCommandMessageRoundTrip()
        throws Exception
    {

        CommandMessage msg = new CommandMessage(CommandMessage.Type.ACTIVATE_BOARD,new ASN1Integer(1));

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DEROutputStream derOut = new DEROutputStream(bos);

        derOut.writeObject(msg.toASN1Primitive());

        ByteArrayInputStream bin = new ByteArrayInputStream(bos.toByteArray());
        ASN1InputStream din = new ASN1InputStream(bin);

        CommandMessage res = CommandMessage.getInstance(din.readObject());

        TestCase.assertEquals(msg.getPayload(), res.getPayload());
        TestCase.assertEquals(msg.getType(), res.getType());
    }


    @Test
    public void testPermutateAndMoveRoundTrip()
        throws Exception
    {

        PermuteAndMoveMessage msg = new PermuteAndMoveMessage("Cat","Doc","Fish","Rabbit");

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DEROutputStream derOut = new DEROutputStream(bos);

        derOut.writeObject(msg.toASN1Primitive());

        ByteArrayInputStream bin = new ByteArrayInputStream(bos.toByteArray());
        ASN1InputStream din = new ASN1InputStream(bin);

        PermuteAndMoveMessage res = PermuteAndMoveMessage.getInstance(din.readObject());

        TestCase.assertEquals(msg.getBoardName(), res.getBoardName());
        TestCase.assertEquals(msg.getDestinationNode(), res.getDestinationNode());
        TestCase.assertEquals(msg.getKeyID(), res.getKeyID());
        TestCase.assertEquals(msg.getTransformName(), res.getTransformName());


    }


}
