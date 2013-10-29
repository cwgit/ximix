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

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.cryptoworkshop.ximix.client.KeyService;
import org.cryptoworkshop.ximix.client.connection.XimixRegistrar;
import org.cryptoworkshop.ximix.client.connection.XimixRegistrarFactory;
import org.cryptoworkshop.ximix.common.util.EventNotifier;

/**
 * Command line tool for fetching a key.
 * <p>
 * For example:
 * <ul>
 *     <li>KeyFetch mixnet.xml EC_ENC</li>
 *     <li>KeyFetch mixnet.xml EC_SIGN</li>
 *     <li>KeyFetch mixnet.xml BLS_SIGN</li>
 * </ul>
 * The public key is returned as a PEM encoded blob, written to standard out.
 * </p>
 */
public class KeyFetch
{
    public static void main(String[] args)
        throws Exception
    {
        if (args.length != 2)
        {
            System.err.println("Usage: KeyFetch mixnet.xml keyID");
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

        KeyService keyService = adminRegistrar.connect(KeyService.class);
        String keyID = args[1];

        try
        {
            byte[] encPubKey = keyService.fetchPublicKey(keyID);

            if (encPubKey == null)
            {
                System.err.println("Public key for ID " + keyID + " not found");
            }
            else
            {
                PemWriter pWrt = new PemWriter(new OutputStreamWriter(System.out));

                pWrt.writeObject(new PemObject("PUBLIC KEY", encPubKey));

                pWrt.close();

                System.err.println("Public key for ID " + keyID + " already exists!");
                System.exit(1);
            }
        }
        finally
        {
            keyService.shutdown();
        }
    }
}
