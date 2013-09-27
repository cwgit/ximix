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

public interface BoardCreationService
    extends Service
{
    /**
     * Create the board boardName using the passed in options.
     *
     * @param boardName the name of the board to create.
     * @param creationOptions the options to use.
     * @exception ServiceConnectionException in case of error.
     */
    void createBoard(String boardName, BoardCreationOptions creationOptions)
        throws ServiceConnectionException;
}