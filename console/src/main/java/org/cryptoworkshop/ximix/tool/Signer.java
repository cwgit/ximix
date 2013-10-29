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

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.cryptoworkshop.ximix.client.QueryService;
import org.cryptoworkshop.ximix.client.SignatureGenerationOptions;
import org.cryptoworkshop.ximix.client.SigningService;
import org.cryptoworkshop.ximix.client.connection.XimixRegistrar;
import org.cryptoworkshop.ximix.client.connection.XimixRegistrarFactory;
import org.cryptoworkshop.ximix.common.crypto.Algorithm;
import org.cryptoworkshop.ximix.common.util.EventNotifier;

/**
 * Command line tool for generating a signature
 * <p>
 * For example:
 * <ul>
 *     <li>Signer mixnet.xml EC_SIGN ECDSA FFEEDD...</li>
 *     <li>Signer mixnet.xml BLS_SIGN BLS FFEEDD...</li>
 * </ul>
 * The result is displayed as a PEM encoded blob.
 * </p>
 */
public class Signer
{
    private static Map<String, Algorithm>  algorithmMap = new HashMap<>();

    static
    {
        algorithmMap.put("ECDSA", Algorithm.ECDSA);
        algorithmMap.put("BLS", Algorithm.BLS);
    }

    public static void main(String[] args)
        throws Exception
    {
        if (args.length != 4)
        {
            System.err.println("Usage: Signer mixnet.xml keyID BLS|ECDSA hex_encoded_hash");
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

        SigningService signingService = adminRegistrar.connect(SigningService.class);
        String keyID = args[1];
        Algorithm algorithm = algorithmMap.get(args[2].toUpperCase());
        byte[] hash = Hex.decode(args[3]);

        try
        {
            byte[] encPubKey = signingService.fetchPublicKey(keyID);

            if (encPubKey != null)
            {
                QueryService queryService = adminRegistrar.connect(QueryService.class);

                Set<String> nodeNames = queryService.getNodeNames();
                int threshold = nodeNames.size() - 1;

                SignatureGenerationOptions keyGenOptions = new SignatureGenerationOptions.Builder(algorithm)
                    .withThreshold(threshold)
                    .withNodes(nodeNames.toArray(new String[nodeNames.size()]))
                    .build();

                encPubKey = signingService.generateSignature(keyID, keyGenOptions, hash);

                PemWriter pWrt = new PemWriter(new OutputStreamWriter(System.out));

                pWrt.writeObject(new PemObject(algorithm.name() + " SIGNATURE", encPubKey));

                pWrt.close();
            }
            else
            {
                System.err.println("Public key for ID " + keyID + " does not exist");
                System.exit(1);
            }
        }
        finally
        {
            signingService.shutdown();
        }
    }
}
