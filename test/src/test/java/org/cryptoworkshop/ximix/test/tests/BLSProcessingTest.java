/**
 * Copyright 2013 Crypto Workshop Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cryptoworkshop.ximix.test.tests;

import java.net.SocketException;

import it.unisa.dia.gas.crypto.jpbc.signature.bls01.engines.BLS01Signer;
import it.unisa.dia.gas.crypto.jpbc.signature.bls01.params.BLS01PublicKeyParameters;
import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.cryptoworkshop.ximix.client.KeyGenerationOptions;
import org.cryptoworkshop.ximix.client.KeyGenerationService;
import org.cryptoworkshop.ximix.client.SignatureGenerationOptions;
import org.cryptoworkshop.ximix.client.SigningService;
import org.cryptoworkshop.ximix.client.XimixRegistrar;
import org.cryptoworkshop.ximix.client.registrar.XimixRegistrarFactory;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.node.XimixNode;
import org.cryptoworkshop.ximix.node.crypto.key.util.BLSPublicKeyFactory;
import org.cryptoworkshop.ximix.test.node.NodeTestUtil;
import org.cryptoworkshop.ximix.test.node.ResourceAnchor;
import org.cryptoworkshop.ximix.test.node.SquelchingThrowableHandler;
import org.junit.Assert;
import org.junit.Test;

import static org.cryptoworkshop.ximix.test.node.NodeTestUtil.getXimixNode;

/**
 *
 */
public class BLSProcessingTest
    extends TestCase
{



    @Override
    public void setUp()
        throws Exception
    {

    }

    @Override
    public void tearDown()
        throws Exception
    {
        NodeTestUtil.shutdownNodes();
    }

    @Test
    public void testBLSSigning()
        throws Exception
    {

        SquelchingThrowableHandler handler = new SquelchingThrowableHandler();

        //
        // Squelch out socket exceptions emitted by close of connections below.
        //
        handler.squelchType(SocketException.class);



        XimixNode nodeOne = getXimixNode("/conf/mixnet.xml", "/conf/node1.xml", handler);
        NodeTestUtil.launch(nodeOne, true);


        XimixNode nodeTwo = getXimixNode("/conf/mixnet.xml", "/conf/node2.xml", handler);
        NodeTestUtil.launch(nodeTwo, true);


        XimixNode nodeThree = getXimixNode("/conf/mixnet.xml", "/conf/node3.xml", handler);
        NodeTestUtil.launch(nodeThree, true);

        XimixNode nodeFour = getXimixNode("/conf/mixnet.xml", "/conf/node4.xml", handler);
        NodeTestUtil.launch(nodeFour, true);

        XimixNode nodeFive = getXimixNode("/conf/mixnet.xml", "/conf/node5.xml", handler);
        NodeTestUtil.launch(nodeFive, true);

        XimixRegistrar registrar = XimixRegistrarFactory.createAdminServiceRegistrar(ResourceAnchor.load("/conf/mixnet.xml"));

        KeyGenerationService keyGenerationService = registrar.connect(KeyGenerationService.class);

        KeyGenerationOptions keyGenOptions = new KeyGenerationOptions.Builder(Algorithm.BLS, "secp256r1")
            .withThreshold(3)
            .withNodes("A", "B", "C", "D")
            .build();

        BLS01PublicKeyParameters sigPubKey = BLSPublicKeyFactory.createKey(keyGenerationService.generatePublicKey("BLSKEY", keyGenOptions));

        SigningService signingService = registrar.connect(SigningService.class);

        SHA256Digest sha256 = new SHA256Digest();

        byte[] message = "hello world!".getBytes();
        byte[] hash = new byte[sha256.getDigestSize()];

        sha256.update(message, 0, message.length);

        sha256.doFinal(hash, 0);

        SignatureGenerationOptions sigGenOptions = new SignatureGenerationOptions.Builder(Algorithm.BLS)
            .withThreshold(3)
            .withNodes("A", "B", "C", "D")
            .build();

        byte[] blsSig = signingService.generateSignature("BLSKEY", sigGenOptions, hash);

        //
        // check the signature locally.
        //
        BLS01Signer signer = new BLS01Signer(sha256);

        signer.init(false, sigPubKey);

        signer.update(message, 0, message.length);

        Assert.assertTrue(signer.verifySignature(blsSig));


        //
        // Shutdown nodes and close services.
        //
        NodeTestUtil.shutdownNodes();
        keyGenerationService.shutdown();
        signingService.shutdown();
    }

    @Test
    public void testWithNodesMixedMissingFromGeneration()
        throws Exception
    {
        SquelchingThrowableHandler handler = new SquelchingThrowableHandler();

        handler.setPrintOnly(true);
        handler.squelchType(SocketException.class);

        //
        // Set up nodes.
        //

        XimixNode nodeOne = getXimixNode("/conf/mixnet.xml", "/conf/node1.xml", handler);
        NodeTestUtil.launch(nodeOne, true);

        XimixNode nodeTwo = getXimixNode("/conf/mixnet.xml", "/conf/node2.xml", handler);
        NodeTestUtil.launch(nodeTwo, true);

        XimixNode nodeThree = getXimixNode("/conf/mixnet.xml", "/conf/node3.xml", handler);
        NodeTestUtil.launch(nodeThree, true);

        XimixNode nodeFour = getXimixNode("/conf/mixnet.xml", "/conf/node4.xml", handler);
        NodeTestUtil.launch(nodeFour, true);

        XimixNode nodeFive = getXimixNode("/conf/mixnet.xml", "/conf/node5.xml", handler);
        NodeTestUtil.launch(nodeFive, true);

        XimixRegistrar adminRegistrar = XimixRegistrarFactory.createAdminServiceRegistrar(ResourceAnchor.load("/conf/mixnet.xml"));

        KeyGenerationService keyGenerationService = adminRegistrar.connect(KeyGenerationService.class);

        KeyGenerationOptions keyGenOptions = new KeyGenerationOptions.Builder(Algorithm.BLS, "d62003-159-158.param")
            .withThreshold(3)
            .withNodes("A", "B", "C", "D", "E" )
            .build();

        BLS01PublicKeyParameters sigPubKey = BLSPublicKeyFactory.createKey(keyGenerationService.generatePublicKey("BLSKEY", keyGenOptions));

        SigningService signingService = adminRegistrar.connect(SigningService.class);

        doMixedMissingTest(signingService, sigPubKey, new String[]{ "A", "B", "C", "D" });
        doMixedMissingTest(signingService, sigPubKey, new String[]{ "A", "D", "C", "B" });
        doMixedMissingTest(signingService, sigPubKey, new String[]{ "D", "E", "B", "A" });
        doMixedMissingTest(signingService, sigPubKey, new String[]{ "D", "E", "B", "C" });

        NodeTestUtil.shutdownNodes();
        keyGenerationService.shutdown();
        signingService.shutdown();
    }

    private void doMixedMissingTest(SigningService signingService, final BLS01PublicKeyParameters sigPubKey, String[] sigNodes)
        throws Exception
    {
        SHA256Digest sha256 = new SHA256Digest();

        byte[] message = "hello world!".getBytes();
        byte[] hash = new byte[sha256.getDigestSize()];

        sha256.update(message, 0, message.length);

        sha256.doFinal(hash, 0);

        SignatureGenerationOptions sigGenOptions = new SignatureGenerationOptions.Builder(Algorithm.BLS)
            .withThreshold(2)
            .withNodes(sigNodes)
            .build();

        byte[] blsSig = signingService.generateSignature("BLSKEY", sigGenOptions, hash);

        //
        // check the signature locally.
        //
        BLS01Signer signer = new BLS01Signer(sha256);

        signer.init(false, sigPubKey);

        signer.update(message, 0, message.length);

        Assert.assertTrue(signer.verifySignature(blsSig));
    }
}
