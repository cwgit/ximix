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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentNavigableMap;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;

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
    private final ConcurrentNavigableMap<Integer,byte[]> boardMap;

    private final ListenerHandler<BulletinBoardBackupListener> listenerHandler;

    private final BulletinBoardBackupListener notifier;

    private final AtomicInteger minimumIndex = new AtomicInteger(0);
    private final AtomicInteger nextIndex = new AtomicInteger(0);

    public BulletinBoardImpl(String boardName, File workingFile, Executor executor)
    {
        this(boardName, workingFile, new DecoupledListenerHandlerFactory(executor).createHandler(BulletinBoardBackupListener.class));
    }

    public BulletinBoardImpl(String boardName, File workingFile, ListenerHandler<BulletinBoardBackupListener> listenerHandler)
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
        this.notifier = listenerHandler.getNotifier();
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

        throw new IllegalStateException("unknown handler requested");
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

    public void postMessage(final byte[] message)
    {
        int index = nextIndex.getAndIncrement();

        boardMap.put(index, message);

        boardDB.commit();

        notifier.messagePosted(this, index, message);
    }

    @Override
    public List<byte[]> getMessages(final int maxNumberOfMessages)
    {
        int count;
        int boardSize = nextIndex.get() - minimumIndex.get();

        if (boardSize > maxNumberOfMessages)
        {
            count = maxNumberOfMessages;
        }
        else
        {
            count = boardSize;
        }

        List<byte[]> rv = new ArrayList<>(count);

        for (int i = 0; i != count; i++)
        {
            rv.add(boardMap.remove(minimumIndex.getAndIncrement()));
        }

        boardDB.commit();

        if (nextIndex.get() - minimumIndex.get() == 0)
        {
            clear();
        }

        return rv;
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

    public Iterator<byte[]> iterator()
    {
        return boardMap.values().iterator();
    }
}
