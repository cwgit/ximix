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
package org.cryptoworkshop.ximix.mixnet.admin;

import org.cryptoworkshop.ximix.common.operation.Operation;
import org.cryptoworkshop.ximix.common.service.ServiceConnectionException;
import org.cryptoworkshop.ximix.mixnet.ShuffleOptions;

public interface ShuffleOperation
{
    /**
     * Do a shuffle.
     * @param boardName
     * @param options
     * @param nodes
     * @throws org.cryptoworkshop.ximix.common.service.ServiceConnectionException
     */
    Operation<ShuffleOperationListener> doShuffleAndMove(
            String boardName,
            ShuffleOptions options,
            String... nodes)
        throws ServiceConnectionException;

}
