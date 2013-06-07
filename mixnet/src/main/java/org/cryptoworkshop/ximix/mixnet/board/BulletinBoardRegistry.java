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
package org.cryptoworkshop.ximix.mixnet.board;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public class BulletinBoardRegistry
{
    private Map<String, BulletinBoard> boards = new HashMap<String, BulletinBoard>();

    private Executor boardUpdateExecutor = Executors.newSingleThreadExecutor();

    public BulletinBoard getBoard(final String boardName)
    {
        synchronized (boards)
        {
            BulletinBoard board = boards.get(boardName);

            // TODO: probably don't want to allow add on demand, should have config up front or special command.
            if (board == null)
            {
                board = new BulletinBoardImpl(boardName, boardUpdateExecutor);

                boards.put(boardName, board);
            }

            return board;
        }
    }

    public BulletinBoard transitBoard(final String boardName)
    {
        synchronized (boards)
        {
            BulletinBoard board = boards.put(boardName, new BulletinBoardImpl(boardName, boardUpdateExecutor));

            // TODO: barf!!  Maybe not here
            if (board == null)
            {

            }

            return board;
        }
    }
}
