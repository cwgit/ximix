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

import org.cryptoworkshop.ximix.client.connection.ServiceConnectionException;
import org.cryptoworkshop.ximix.common.util.Operation;

/**
 * Support interface for requesting a shuffle.
 */
public interface ShuffleOperation
{
    /**
     * Do a shuffle. If a shuffle is to be repeated on a node twice, repeat the node name in the nodes argument.
     *
     * @param boardName board to do the shuffle on.
     * @param options applicable shuffle options to use.
     * @param defaultListener initial listener to monitor a shuffle operation.
     * @param nodes the node path to use.
     * @throws org.cryptoworkshop.ximix.client.connection.ServiceConnectionException
     */
    Operation<ShuffleOperationListener> doShuffleAndMove(
            String boardName,
            ShuffleOptions options,
            ShuffleOperationListener defaultListener,
            String... nodes)
        throws ServiceConnectionException;
}
