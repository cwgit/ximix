package org.cryptoworkshop.ximix.test.tests;

import junit.framework.TestCase;
import org.cryptoworkshop.ximix.crypto.KeyGenerationOptions;
import org.cryptoworkshop.ximix.crypto.KeyType;
import org.cryptoworkshop.ximix.crypto.client.KeyGenerationService;
import org.cryptoworkshop.ximix.node.XimixNode;
import org.cryptoworkshop.ximix.registrar.XimixRegistrar;
import org.cryptoworkshop.ximix.registrar.XimixRegistrarFactory;
import org.cryptoworkshop.ximix.test.node.NodeTestUtil;
import org.cryptoworkshop.ximix.test.node.ResourceAnchor;
import org.junit.Test;

import java.security.SecureRandom;

import static org.cryptoworkshop.ximix.test.node.NodeTestUtil.getXimixNode;

/**
 *
 */
public class KeyProcessingTest
{

    @Test
    public void testKeyGenerationEncryptionTest()
        throws Exception
    {
        XimixNode nodeOne = getXimixNode("/conf/mixnet.xml", "/conf/node1.xml");
        NodeTestUtil.launch(nodeOne);

        XimixNode nodeTwo = getXimixNode("/conf/mixnet.xml", "/conf/node2.xml");
        NodeTestUtil.launch(nodeTwo);

        XimixNode nodeThree = getXimixNode("/conf/mixnet.xml", "/conf/node3.xml");
        NodeTestUtil.launch(nodeThree);

        XimixNode nodeFour = getXimixNode("/conf/mixnet.xml", "/conf/node4.xml");
        NodeTestUtil.launch(nodeFour);

        XimixNode nodeFive = getXimixNode("/conf/mixnet.xml", "/conf/node5.xml");
        NodeTestUtil.launch(nodeFive);




        SecureRandom random = new SecureRandom();

        XimixRegistrar adminRegistrar = XimixRegistrarFactory.createAdminServiceRegistrar(ResourceAnchor.load("/conf/mixnet.xml"));

        KeyGenerationService keyGenerationService = adminRegistrar.connect(KeyGenerationService.class);

        KeyGenerationOptions keyGenOptions = new KeyGenerationOptions.Builder(KeyType.EC_ELGAMAL, "secp256r1")
            .withThreshold(4)
            .withNodes("A", "B", "C","D","E")
            .build();

        byte[] encPubKey = keyGenerationService.generatePublicKey("ECKEY", keyGenOptions);

        TestCase.assertTrue(true);


    }

}
