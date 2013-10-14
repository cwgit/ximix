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
package org.cryptoworkshop.ximix.node.mixnet.board;

import java.io.File;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentNavigableMap;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;

import org.cryptoworkshop.ximix.common.asn1.message.MessageWitness;
import org.cryptoworkshop.ximix.common.asn1.message.MessageWitnessBlock;
import org.cryptoworkshop.ximix.common.asn1.message.PostedData;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessage;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessageBlock;
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptBlock;
import org.cryptoworkshop.ximix.common.util.DecoupledListenerHandlerFactory;
import org.cryptoworkshop.ximix.common.util.EventNotifier;
import org.cryptoworkshop.ximix.common.util.ListenerHandler;
import org.cryptoworkshop.ximix.common.util.TranscriptType;
import org.cryptoworkshop.ximix.node.mixnet.util.IndexNumberGenerator;
import org.mapdb.DB;
import org.mapdb.DBMaker;

/**
 * Default implementation of a bulletin board.
 */
public class BulletinBoardImpl
    implements BulletinBoard
{
    private final String boardName;
    private final File workingFile;
    private final DB boardDB;
    private final ConcurrentNavigableMap<Integer, byte[]> boardMap;
    private final ConcurrentNavigableMap<Integer, byte[]> commitmentMap;
    private final ConcurrentNavigableMap<Integer, byte[]> witnessMap;

    private final ListenerHandler<BulletinBoardBackupListener> backupListenerHandler;
    private final ListenerHandler<BulletinBoardChangeListener> changeListenerHandler;


    private final BulletinBoardBackupListener backupNotifier;
    private final BulletinBoardChangeListener changeNotifier;

    private final AtomicInteger minimumIndex = new AtomicInteger(0);
    private final AtomicInteger nextIndex = new AtomicInteger(0);

    public BulletinBoardImpl(String boardName, File workingFile, Executor executor, EventNotifier eventNotifier)
    {
        this(boardName, workingFile, new DecoupledListenerHandlerFactory(executor, eventNotifier).createHandler(BulletinBoardBackupListener.class), new DecoupledListenerHandlerFactory(executor, eventNotifier).createHandler(BulletinBoardChangeListener.class));
    }

    private BulletinBoardImpl(String boardName, File workingFile, ListenerHandler<BulletinBoardBackupListener> backupListenerHandler, ListenerHandler<BulletinBoardChangeListener> changeListenerHandler)
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
        commitmentMap = boardDB.getTreeMap("commitments");
        witnessMap = boardDB.getTreeMap(WITNESSES);

        nextIndex.set(boardMap.size());

        this.backupListenerHandler = backupListenerHandler;
        this.changeListenerHandler = changeListenerHandler;

        this.backupNotifier = backupListenerHandler.getNotifier();
        this.changeNotifier = changeListenerHandler.getNotifier();
    }

    @Override
    public void addListener(BulletinBoardBackupListener bulletinBoardBackupListener)
    {
        backupListenerHandler.addListener(bulletinBoardBackupListener);
    }

    @Override
    public <T> ListenerHandler<T> getListenerHandler(Class<T> listenerClass)
    {
        if (BulletinBoardBackupListener.class.isAssignableFrom(listenerClass))
        {
            return (ListenerHandler<T>)backupListenerHandler;
        }
        else if (BulletinBoardChangeListener.class.isAssignableFrom(listenerClass))
        {
            return (ListenerHandler<T>)changeListenerHandler;
        }

        throw new IllegalStateException("unknown handler requested");
    }

    @Override
    public void addListener(BulletinBoardChangeListener listener)
    {
        changeListenerHandler.addListener(listener);
    }

    @Override
    public TranscriptBlock fetchTranscriptData(TranscriptType dataClass, IndexNumberGenerator indexGenerator, TranscriptBlock.Builder responseBuilder)
    {
        if (TranscriptType.WITNESSES == dataClass)
        {
            while (indexGenerator.hasNext() && !responseBuilder.isFull())
            {
                int index = indexGenerator.nextIndex();

                responseBuilder.add(new PostedData(index, witnessMap.get(index)));
            }
        }
        else
        {
            while (indexGenerator.hasNext() && !responseBuilder.isFull())
            {
                int index = indexGenerator.nextIndex();

                responseBuilder.add(new PostedMessage(index, boardMap.get(index), commitmentMap.get(index)));
            }
        }

        return responseBuilder.build();
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

    public int transcriptSize(TranscriptType transcriptType)
    {
        if (TranscriptType.WITNESSES == transcriptType)
        {
            return witnessMap.size();
        }
        else
        {
            return boardMap.size();
        }
    }

    public void postMessage(final byte[] message)
    {
        int index = nextIndex.getAndIncrement();

        boardMap.put(index, message);

        boardDB.commit();

        backupNotifier.messagePosted(this, index, message);

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
            if (message.hasCommitment())
            {
                commitmentMap.put(message.getIndex(), message.getCommitment());
            }
            if (message.getIndex() >= maxIndex)
            {
                maxIndex = message.getIndex() + 1;    // nextIndex is the number of the next free slot
            }
        }

        nextIndex.set(maxIndex);

        boardDB.commit();

        for (PostedMessage message : messages)
        {
            backupNotifier.messagePosted(this, message.getIndex(), message.getMessage());
        }
    }

    @Override
    public PostedMessageBlock removeMessages(PostedMessageBlock.Builder blockBuilder)
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

            blockBuilder.add(index,  boardMap.remove(index));
        }

        boardDB.commit();

        if (nextIndex.get() - minimumIndex.get() == 0)
        {
            clear();
        }
        PostedMessageBlock pmb = blockBuilder.build();

        changeNotifier.messagesRemoved(this, pmb.getMessages().size());
        return pmb;
    }

    @Override
    public void postWitnessBlock(MessageWitnessBlock witnessBlock)
    {
        List<MessageWitness> witnesses = witnessBlock.getWitnesses();

        for (MessageWitness messageWitness : witnesses)
        {
            try
            {
                witnessMap.put(messageWitness.getIndex(), messageWitness.getWitness().getEncoded());
            }
            catch (IOException e)
            {
                // TODO: this should never happen, so perhaps IllegalState or maybe log.
                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            }
        }

        boardDB.commit();
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

        backupNotifier.cleared(this);
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
