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
package org.cryptoworkshop.ximix.crypto.client;

import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;

public interface KeyService
{
    /**
     * Return the public key associated with key ID keyID.
     *
     * @param keyID the id of the key we are looking for.
     * @return a byte[] array of the SubjectPublicKeyInfo object representing the key.
     */
    byte[] fetchPublicKey(String keyID)
        throws ServiceConnectionException;

    /**
     * Return the partial public key associated with key ID keyID for a particular node in the network.
     *
     * @param nodeID the node we are interested in
     * @param keyID the id of the key we are looking for.
     * @return a byte[] array of the SubjectPublicKeyInfo object representing the key.
     */
    byte[] fetchPublicKey(String nodeID, String keyID)
        throws ServiceConnectionException;
}
