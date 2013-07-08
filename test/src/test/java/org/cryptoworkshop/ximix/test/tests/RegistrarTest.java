package org.cryptoworkshop.ximix.test.tests;

import junit.framework.TestCase;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.crypto.KeyGenerationOptions;
import org.cryptoworkshop.ximix.crypto.KeyType;
import org.cryptoworkshop.ximix.crypto.client.KeyGenerationService;
import org.cryptoworkshop.ximix.registrar.XimixRegistrar;
import org.cryptoworkshop.ximix.registrar.XimixRegistrarFactory;
import org.cryptoworkshop.ximix.test.node.ResourceAnchor;
import org.junit.Test;

/**
 *
 */
public class RegistrarTest
{

    /**
     * Test the correct exception is thrown when the admin service cannot find a node.
     *
     * @throws Exception
     */
    @Test
    public void testRegistrarWithNoStart()
        throws Exception
    {

        XimixRegistrar adminRegistrar = XimixRegistrarFactory.createAdminServiceRegistrar(ResourceAnchor.load("/conf/mixnet.xml"));
        KeyGenerationService keyGenerationService = adminRegistrar.connect(KeyGenerationService.class);
        try
        {

            KeyGenerationOptions keyGenOptions = new KeyGenerationOptions.Builder(KeyType.EC_ELGAMAL, "secp256r1")
                .withThreshold(2)
                .withNodes("A", "B")
                .build();
            byte[] encPubKey = keyGenerationService.generatePublicKey("ECKEY", keyGenOptions);

            TestCase.fail();
        }
        catch (ServiceConnectionException rse)
        {
            TestCase.assertTrue(true);
        }

        keyGenerationService.shutdown();


    }
}
