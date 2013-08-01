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

import java.io.File;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentNavigableMap;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;

import org.cryptoworkshop.ximix.common.message.PostedMessage;
import org.cryptoworkshop.ximix.common.message.PostedMessageBlock;
import org.cryptoworkshop.ximix.common.util.DecoupledListenerHandlerFactory;
import org.cryptoworkshop.ximix.common.util.ListenerHandler;
import org.mapdb.DB;
import org.mapdb.DBMaker;

public class BulletinBoardImpl
    implements BulletinBoard
{
    private final String boardName;
    private final File workingFile;
    private final DB boardDB;
    private final ConcurrentNavigableMap<Integer, byte[]> boardMap;

    private final ListenerHandler<BulletinBoardBackupListener> listenerHandler;
    private final ListenerHandler<BulletinBoardChangeListener> changeListenerHandler;


    private final BulletinBoardBackupListener notifier;
    private final BulletinBoardChangeListener changeNotifier;

    private final AtomicInteger minimumIndex = new AtomicInteger(0);
    private final AtomicInteger nextIndex = new AtomicInteger(0);


    public BulletinBoardImpl(String boardName, File workingFile, Executor executor)
    {
        this(boardName, workingFile, new DecoupledListenerHandlerFactory(executor).createHandler(BulletinBoardBackupListener.class), new DecoupledListenerHandlerFactory(executor).createHandler(BulletinBoardChangeListener.class));
    }

    public BulletinBoardImpl(String boardName, File workingFile, ListenerHandler<BulletinBoardBackupListener> listenerHandler, ListenerHandler<BulletinBoardChangeListener> changeListenerHandler)
    {
        this.boardName = boardName;

        if (workingFile != null)
        {
            this.workingFile = workingFile;

            boardDB = DBMaker.newFileDB(workingFile)
                .closeOnJvmShutdown()
                .make();
        }
        else
        {
            this.workingFile = null;
            boardDB = DBMaker.newMemoryDB()
                .closeOnJvmShutdown()
                .make();
        }

        boardMap = boardDB.getTreeMap(boardName);

        nextIndex.set(boardMap.size());

        this.listenerHandler = listenerHandler;
        this.changeListenerHandler = changeListenerHandler;

        this.notifier = listenerHandler.getNotifier();
        this.changeNotifier = changeListenerHandler.getNotifier();

    }

    @Override
    public void addListener(BulletinBoardBackupListener bulletinBoardBackupListener)
    {
        listenerHandler.addListener(bulletinBoardBackupListener);
    }

    @Override
    public <T> ListenerHandler<T> getListenerHandler(Class<T> listenerClass)
    {
        if (BulletinBoardBackupListener.class.isAssignableFrom(listenerClass))
        {
            return (ListenerHandler<T>)listenerHandler;
        }
        else if (BulletinBoardChangeListener.class.isAssignableFrom(listenerClass))
        {
            return (ListenerHandler<T>)listenerHandler;
        }

        throw new IllegalStateException("unknown handler requested");
    }

    @Override
    public void addListener(BulletinBoardChangeListener listener)
    {
        changeListenerHandler.addListener(listener);
    }

    @Override
    public void shutdown()
    {
        boardDB.close();
    }

    public String getName()
    {
        return boardName;
    }

    public int size()
    {
        return nextIndex.get();
    }

    public void postMessage(final byte[] message)
    {
        int index = nextIndex.getAndIncrement();

        boardMap.put(index, message);

        boardDB.commit();

        notifier.messagePosted(this, index, message);

        changeNotifier.messagesAdded(this, 1);


    }

    @Override
    public void postMessageBlock(PostedMessageBlock messageBlock)
    {
        List<PostedMessage> messages = messageBlock.getMessages();

        int maxIndex = nextIndex.get();

        for (PostedMessage message : messages)
        {
            boardMap.put(message.getIndex(), message.getMessage());
            if (message.getIndex() >= maxIndex)
            {
                maxIndex = message.getIndex() + 1;    // nextIndex is the number of the next free slot
            }
        }

        nextIndex.set(maxIndex);

        boardDB.commit();

        for (PostedMessage message : messages)
        {
            notifier.messagePosted(this, message.getIndex(), message.getMessage());
        }
        changeNotifier.messagesAdded(this, messages.size());

    }

    @Override
    public PostedMessageBlock getMessages(PostedMessageBlock.Builder blockBuilder)
    {
        int count;
        int boardSize = nextIndex.get() - minimumIndex.get();

        if (boardSize > blockBuilder.capacity())
        {
            count = blockBuilder.capacity();
        }
        else
        {
            count = boardSize;
        }

        for (int i = 0; i != count; i++)
        {
            int index = minimumIndex.getAndIncrement();

            blockBuilder.add(index, boardMap.remove(index));
        }

        boardDB.commit();

        if (nextIndex.get() - minimumIndex.get() == 0)
        {
            clear();
        }

        return blockBuilder.build();
    }

    @Override
    public void clear()
    {
        boardMap.clear();
        minimumIndex.set(0);
        nextIndex.set(0);
        boardDB.commit();

        if (workingFile != null)
        {
            boardDB.compact();
        }

        notifier.cleared(this);
    }

    public Iterator<PostedMessage> iterator()
    {
        return new Iterator<PostedMessage>()
        {
            Iterator<Integer> keys = boardMap.keySet().iterator();

            @Override
            public boolean hasNext()
            {
                return keys.hasNext();
            }

            @Override
            public PostedMessage next()
            {
                Integer next = keys.next();
                return new PostedMessage(next, boardMap.get(next));
            }

            @Override
            public void remove()
            {
                throw new UnsupportedOperationException("cannot remove message from board this way!");
            }
        };
    }
}
