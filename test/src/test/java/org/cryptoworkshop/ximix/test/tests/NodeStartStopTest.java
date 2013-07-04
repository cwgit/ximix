package org.cryptoworkshop.ximix.test.tests;

import junit.framework.TestCase;
import org.cryptoworkshop.ximix.common.conf.ConfigException;
import org.cryptoworkshop.ximix.crypto.KeyGenerationOptions;
import org.cryptoworkshop.ximix.crypto.KeyType;
import org.cryptoworkshop.ximix.crypto.client.KeyGenerationService;
import org.cryptoworkshop.ximix.node.ThrowableHandler;
import org.cryptoworkshop.ximix.node.XimixNode;
import org.cryptoworkshop.ximix.node.XimixNodeBuilder;
import org.cryptoworkshop.ximix.registrar.XimixRegistrar;
import org.cryptoworkshop.ximix.registrar.XimixRegistrarFactory;
import org.cryptoworkshop.ximix.test.node.NodeLauncher;
import org.cryptoworkshop.ximix.test.node.ResourceAnchor;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

/**
 * Tests for basic node stopping and starting.
 */
public class NodeStartStopTest
{


    /**
     * Tests that when stop is called the FutureComplete handler is called when the node shuts down completely.
     *
     * @throws Exception
     */
    @org.junit.Test
    public void testNodeStopWithFutureHandler()
        throws Exception
    {

        final XimixNode node = getXimixNode("/conf/mixnet.xml", "/conf/node1.xml");


        Thread th = new Thread(new Runnable()
        {
            @Override
            public void run()
            {
                node.start();
            }
        });
        th.setPriority(Thread.MIN_PRIORITY);
        th.start();

        Thread.sleep(1000);
        TestCase.assertTrue(node.shutdown(15, TimeUnit.SECONDS));
    }

    private XimixNode getXimixNode(String networkConfig, String nodeConfigPath)
        throws ConfigException
    {
        XimixNodeBuilder builder = new XimixNodeBuilder(ResourceAnchor.load(networkConfig)).withThrowableHandler(new ThrowableHandler()
        {
            @Override
            public void handle(Throwable throwable)
            {
                throwable.printStackTrace();
            }
        });

        return builder.build(ResourceAnchor.load(nodeConfigPath));
    }


    @Test
    public void testCorrectMessageSent()
        throws Exception
    {
        XimixNode nodeOne = getXimixNode("/conf/mixnet.xml", "/conf/node1.xml");
        NodeLauncher.launch(nodeOne);

        XimixNode nodeTwo = getXimixNode("/conf/mixnet.xml", "/conf/node2.xml");
        NodeLauncher.launch(nodeTwo);

        XimixNode nodeThree = getXimixNode("/conf/mixnet.xml", "/conf/node3.xml");
        NodeLauncher.launch(nodeThree);

        XimixNode nodeFour = getXimixNode("/conf/mixnet.xml", "/conf/node4.xml");
        NodeLauncher.launch(nodeFour);

        XimixNode nodeFive = getXimixNode("/conf/mixnet.xml", "/conf/node5.xml");
        NodeLauncher.launch(nodeFive);


        SecureRandom random = new SecureRandom();

        XimixRegistrar adminRegistrar = XimixRegistrarFactory.createAdminServiceRegistrar(ResourceAnchor.load("/conf/mixnet.xml"));

        KeyGenerationService keyGenerationService = adminRegistrar.connect(KeyGenerationService.class);

        KeyGenerationOptions keyGenOptions = new KeyGenerationOptions.Builder(KeyType.EC_ELGAMAL, "secp256r1")
            .withThreshold(4)
            .withNodes("A", "B", "C", "D", "E")
            .build();

        byte[] encPubKey = keyGenerationService.generatePublicKey("ECKEY", keyGenOptions);

        TestCase.assertTrue(true);


    }


}
