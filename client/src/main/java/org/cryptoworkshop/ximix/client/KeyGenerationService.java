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
package org.cryptoworkshop.ximix.client;

import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;

public interface KeyGenerationService
    extends KeyService
{
    /**
     * Generate a public key and associate it with key ID keyID. The key is returned if generated successfully.
     *
     * @param keyID         the id of the key we are looking for.
     * @param keyGenOptions options applicable to this key generation.
     * @return a byte[] array of the SubjectPublicKeyInfo object representing the key.
     */
    byte[] generatePublicKey(String keyID, KeyGenerationOptions keyGenOptions)
        throws ServiceConnectionException;

    void shutdown()
        throws ServiceConnectionException;
}
