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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.FutureTask;

import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;

/**
 * A scheduler for board events - we use this to make sure that the board processing is multi-threaded, but only one thread is executing on a board at a time.
 */
public class BoardExecutor
{
    private final Executor decoupler;
    private final ExecutorService scheduledExecutor;
    private final Set<String> executing = new HashSet();
    private final List<BoardTask> pending = new LinkedList<>();

    /**
     * Base constructor.
     *
     * @param decoupler a single threaded decoupler.
     * @param scheduledExecutor a multi-threaded task executor.
     */
    public BoardExecutor(Executor decoupler, ExecutorService scheduledExecutor)
    {
        this.decoupler = decoupler;
        this.scheduledExecutor = scheduledExecutor;
    }

    /**
     * Submit a task for a particular board.
     *
     * The task will be executed after any other currently running tasks for that board are done.
     *
     * @param boardName name of the board the task is for.
     * @param task a callable representing the task to be performed.
     * @return a Future returning the appropriate MessageReply.
     */
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

    public FutureTask<MessageReply> submitBackupTask(final String boardName, final Callable<MessageReply> task)
    {
        return submitTask(boardName + ".backup", task);
    }

    private void moveToExecuteQueue(BoardTask boardTask)
    {
        executing.add(boardTask.getBoardName());

        scheduledExecutor.submit(boardTask);
    }

    public void execute(Runnable task)
    {
        decoupler.execute(task);
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
