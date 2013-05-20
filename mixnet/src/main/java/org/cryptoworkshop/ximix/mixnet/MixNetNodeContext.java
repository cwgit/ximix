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
package org.cryptoworkshop.ximix.mixnet;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import org.cryptoworkshop.ximix.mixnet.board.BulletinBoard;

public class MixNetNodeContext
{
    private Executor boardUpdateExecutor = Executors.newSingleThreadExecutor();
    private Executor multiTaskExecutor = Executors.newCachedThreadPool();

    private Map<String, BulletinBoard> boards = new HashMap<String, BulletinBoard>();

    public void addConnection(Runnable task)
    {
        multiTaskExecutor.execute(task);
    }

    public void scheduleTask(Runnable task)
    {
        multiTaskExecutor.execute(task);
    }

    public BulletinBoard getBoard(final String boardName)
    {
        synchronized (boards)
        {
            BulletinBoard board = boards.get(boardName);

            // TODO: probably don't want to allow add on demand, should have config up front or special command.
            if (board == null)
            {
                board = new BulletinBoard(boardName, boardUpdateExecutor);

                boards.put(boardName, board);
            }

            return board;
        }
    }
}
