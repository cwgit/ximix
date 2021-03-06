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
 * Interface defining available download operations.
 */
public interface DownloadOperation
{
    /**
     * Download the contents of a board.
     *
     * @param boardName name of the board to download from.
     * @param options
     * @param defaultListener the listener to be sent messages
     */
    Operation<DownloadOperationListener> downloadBoardContents(
            String boardName,
            DownloadOptions options,
            DownloadOperationListener defaultListener)
        throws ServiceConnectionException;
}
