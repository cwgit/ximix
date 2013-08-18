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

/**
 * Carrier service interface for methods associated with signing.
 */
public interface SigningService
    extends KeyService
{
    /**
     * Generate a signature using the given keyID and options for the passed in message. The type of signature
     * is determined by the algorithm associated with keyID, and a byte encoding suitable for verification is returned.
     *
     * @param keyID the id for the key to be used in signing.
     * @param options any options required for the signature generation.
     * @param message the message to be signed.
     * @return a byte[] encoding of the signature in a format suitable for later verification.
     * @throws ServiceConnectionException in case of failure.
     */
    byte[] generateSignature(String keyID, SignatureGenerationOptions options, byte[] message)
        throws ServiceConnectionException;
}
