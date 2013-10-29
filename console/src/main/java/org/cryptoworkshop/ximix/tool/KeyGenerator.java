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
package org.cryptoworkshop.ximix.tool;

import java.io.File;
import java.io.OutputStreamWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.cryptoworkshop.ximix.client.KeyGenerationOptions;
import org.cryptoworkshop.ximix.client.KeyGenerationService;
import org.cryptoworkshop.ximix.client.QueryService;
import org.cryptoworkshop.ximix.client.connection.XimixRegistrar;
import org.cryptoworkshop.ximix.client.connection.XimixRegistrarFactory;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.common.util.EventNotifier;

/**
 * Command line tool for generating a key.
 * <p>
 * For example:
 * <ul>
 *     <li>KeyGenerator mixnet.xml EC_ENC EC_ELGAMAL secp256r1</li>
 *     <li>KeyGenerator mixnet.xml EC_SIGN ECDSA secp256r1</li>
 *     <li>KeyGenerator mixnet.xml BLS_SIGN BLS d62003-159-158.param</li>
 * </ul>
 * The generated public key is returned as a PEM encoded blob, written to standard out.
 * </p>
 */
public class KeyGenerator
{
    private static Map<String, Algorithm>  algorithmMap = new HashMap<>();

    static
    {
        algorithmMap.put("ECDSA", Algorithm.ECDSA);
        algorithmMap.put("EC_ELGAMAL", Algorithm.EC_ELGAMAL);
        algorithmMap.put("ECELGAMAL", Algorithm.EC_ELGAMAL);
        algorithmMap.put("BLS", Algorithm.BLS);
    }

    public static void main(String[] args)
        throws Exception
    {
        if (args.length != 4)
        {
            System.err.println("Usage: KeyGenerator mixnet.xml keyID BLS|EC_ELGAMAL|ECDSA domain_parameters_name");
            System.exit(1);
        }

        XimixRegistrar adminRegistrar = XimixRegistrarFactory.createAdminServiceRegistrar(new File(args[0]), new EventNotifier()
        {
            @Override
            public void notify(Level level, Throwable throwable)
            {
                System.err.print(level + " " + throwable.getMessage());
                throwable.printStackTrace(System.err);
            }

            @Override
            public void notify(Level level, Object detail)
            {
                System.err.println(level + " " + detail.toString());
            }

            @Override
            public void notify(Level level, Object detail, Throwable throwable)
            {
                System.err.println(level + " " + detail.toString());
                throwable.printStackTrace(System.err);
            }
        });

        KeyGenerationService keyGenerationService = adminRegistrar.connect(KeyGenerationService.class);
        String keyID = args[1];
        Algorithm algorithm = algorithmMap.get(args[2].toUpperCase());
        String params = args[3];

        try
        {
            byte[] encPubKey = keyGenerationService.fetchPublicKey(keyID);

            if (encPubKey == null)
            {
                QueryService queryService = adminRegistrar.connect(QueryService.class);

                Set<String> nodeNames = queryService.getNodeNames();
                int threshold = nodeNames.size() - 1;

                KeyGenerationOptions keyGenOptions = new KeyGenerationOptions.Builder(algorithm, params)
                    .withThreshold(threshold)
                    .withNodes(nodeNames.toArray(new String[nodeNames.size()]))
                    .build();

                encPubKey = keyGenerationService.generatePublicKey(keyID, keyGenOptions);

                PemWriter pWrt = new PemWriter(new OutputStreamWriter(System.out));

                pWrt.writeObject(new PemObject("PUBLIC KEY", encPubKey));

                pWrt.close();
            }
            else
            {
                System.err.println("Public key for ID " + keyID + " already exists!");
                System.exit(1);
            }
        }
        finally
        {
            keyGenerationService.shutdown();
        }
    }
}
