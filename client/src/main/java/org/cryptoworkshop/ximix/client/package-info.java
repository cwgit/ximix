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
/**
Base classes for writing a Ximix client.
<p>
Clients are created via a XimixRegistrar. For example a simple client which simply retrieves a Ximix EC public key for encryption or signature verifications may look like this:
    <pre>
    XimixRegistrar registrar = XimixRegistrarFactory.createServicesRegistrar(configFile);

    KeyService    keyFetcher = registrar.connect(KeyService.class);

    byte[] encPubKey = keyFetcher.fetchPublicKey("ECKEY");
    </pre>
</p>
See the JavaDoc for the service of interest for specific details.
*/
package org.cryptoworkshop.ximix.client;


