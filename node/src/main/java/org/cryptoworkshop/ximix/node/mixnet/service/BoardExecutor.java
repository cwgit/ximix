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
package org.cryptoworkshop.ximix.node.mixnet.service;

import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.FutureTask;
import java.util.concurrent.ScheduledExecutorService;

import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;

/**
 * A scheduler for board events - we use this to make sure that the board processing is multi-threaded, but only one thread is executing on a board at a time.
 */
public class BoardExecutor
{
    private final Executor decoupler;
    private final ScheduledExecutorService scheduledExecutor;
    private final Set<String> executing = new HashSet();
    private final List<BoardTask> pending = new LinkedList<>();

    public BoardExecutor(Executor decoupler, ScheduledExecutorService scheduledExecutor)
    {
        this.decoupler = decoupler;
        this.scheduledExecutor = scheduledExecutor;
    }

    public FutureTask<MessageReply> submitTask(final String boardName, final Callable<MessageReply> task)
    {
        final BoardTask boardTask = new BoardTask(boardName, new Callable<MessageReply>()
        {
            @Override
            public MessageReply call()
                throws Exception
            {
                try
                {
                    return task.call();
                }
                finally
                {
                    decoupler.execute(new ClearTask(boardName));
                }
            }
        });

        decoupler.execute(new Runnable()
        {
            @Override
            public void run()
            {
                if (executing.contains(boardName))
                {
                    pending.add(boardTask);
                }
                else
                {
                    moveToExecuteQueue(boardTask);
                }
            }
        });

        return boardTask;
    }

    private void moveToExecuteQueue(BoardTask boardTask)
    {
        executing.add(boardTask.getBoardName());

        scheduledExecutor.submit(boardTask);
    }

    private class BoardTask
        extends FutureTask<MessageReply>
    {
        private final String name;

        BoardTask(String name, Callable<MessageReply> callable)
        {
            super(callable);

            this.name = name;
        }

        public String getBoardName()
        {
            return name;
        }
    }

    private class ClearTask
        implements Runnable
    {
        private final String boardName;

        private ClearTask(String boardName)
        {
            this.boardName = boardName;
        }

        @Override
        public void run()
        {
            executing.remove(boardName);

            for (Iterator<BoardTask> it = pending.iterator(); it.hasNext(); )
            {
                BoardTask task = it.next();

                if (boardName.equals(task.getBoardName()))
                {
                    moveToExecuteQueue(task);

                    it.remove();

                    return;
                }
            }
        }
    }
}
