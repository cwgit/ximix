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
package org.cryptoworkshop.ximix.node.crypto.key;

/**
 * Basic interface describing a listener for a KeyManager
 */
public interface KeyManagerListener
{
    /**
     * Signal a key has been added.
     *
     * @param keyManager the key manager causing this event.
     * @param keyID the ID of the key that was added.
     */
    void keyAdded(KeyManager keyManager, String keyID);
}
