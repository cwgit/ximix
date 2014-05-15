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

import java.util.Map;

import org.cryptoworkshop.ximix.common.util.OperationListener;

/**
 * Listener for monitoring shuffle operations.
 */
public interface ShuffleOperationListener
    extends OperationListener<ShuffleStatus>
{
    /**
     * Called to pass in the commitments for seeds for later transcript recovery committed to by the nodes in
     * the shuffle.
     *
     * @param seedCommitments a map of node name, byte[] pairs. The byte[] represents a CMS SignedData object
     *                        containing a SeedCommitmentMessage.
     */
    void commit(Map<String, byte[]> seedCommitments);
}
