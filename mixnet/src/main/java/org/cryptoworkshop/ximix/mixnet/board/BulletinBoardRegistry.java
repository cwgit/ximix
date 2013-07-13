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
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executor;

import org.cryptoworkshop.ximix.mixnet.transform.Transform;

public class BulletinBoardRegistry
{
    private Map<String, BulletinBoard> boards = new HashMap<String, BulletinBoard>();
    private Map<String, BulletinBoard> transitBoards = new HashMap<String, BulletinBoard>();
    private Set<String>                suspendedBoards = new HashSet<>();
    private Set<String>                dowloadLockedBoards = new HashSet<>();
    private Set<String>                shuffleLockedBoards = new HashSet<>();

    private Set<String>                inTransitBoards = new HashSet<>();
    private Set<String>                completedBoards = new HashSet<>();

    private final Map<String, Transform> transforms;
    private final Executor boardUpdateExecutor;

    public BulletinBoardRegistry(Map<String, Transform> transforms, Executor boardUpdateExecutor)
    {
        this.transforms = transforms;
        this.boardUpdateExecutor = boardUpdateExecutor;
    }

    public BulletinBoard createBoard(final String boardName)
    {
        synchronized (boards)
        {
            BulletinBoard board = boards.get(boardName);

            // TODO: need to detect twice!
            if (board == null)
            {
                board = new BulletinBoardImpl(boardName, transforms, boardUpdateExecutor);

                boards.put(boardName, board);
            }

            return board;
        }
    }

    public BulletinBoard getBoard(final String boardName)
    {
        synchronized (boards)
        {
            return boards.get(boardName);
        }
    }

    public BulletinBoard transitBoard(final String boardName)
    {
        synchronized (boards)
        {
            BulletinBoard board = null; //boards.put(boardName, new BulletinBoardImpl(boardName, boardUpdateExecutor));

            // TODO: barf!!  Maybe not here
            if (board == null)
            {

            }

            return board;
        }
    }

    public String[] getBoardNames()
    {
        return boards.keySet().toArray(new String[boards.size()]);
    }

    public boolean isSuspended(String boardName)
    {
        synchronized (boards)
        {
            return suspendedBoards.contains(boardName);
        }
    }

    public void activateBoard(String boardName)
    {
        synchronized (boards)
        {
            suspendedBoards.remove(boardName);
        }
    }

    public void suspendBoard(String boardName)
    {
        synchronized (boards)
        {
            suspendedBoards.add(boardName);
        }
    }

    public boolean isLocked(String boardName)
    {
        return isDownloadLocked(boardName) || isShuffleLocked(boardName) || isSuspended(boardName);
    }

    public boolean isDownloadLocked(String boardName)
    {
        synchronized (boards)
        {
            return dowloadLockedBoards.contains(boardName);
        }
    }

    public void downloadLock(String boardName)
    {
        synchronized (boards)
        {
            dowloadLockedBoards.add(boardName);
        }
    }

    public void downloadUnlock(String boardName)
    {
        synchronized (boards)
        {
            dowloadLockedBoards.remove(boardName);
        }
    }

    public boolean isShuffleLocked(String boardName)
    {
        synchronized (boards)
        {
            return shuffleLockedBoards.contains(boardName);
        }
    }

    public void shuffleLock(String boardName)
    {
        synchronized (boards)
        {
            shuffleLockedBoards.add(boardName);
        }
    }

    public void shuffleUnlock(String boardName)
    {
        synchronized (boards)
        {
            shuffleLockedBoards.remove(boardName);
        }
    }

    public boolean hasBoard(String boardName)
    {
        synchronized (boards)
        {
            return boards.containsKey(boardName);
        }
    }

    public BulletinBoard getTransitBoard(String boardName)
    {
        synchronized (boards)
        {
            BulletinBoard board = transitBoards.get(boardName);

            // TODO: need to detect twice!
            if (board == null)
            {
                board = new BulletinBoardImpl(boardName, transforms, boardUpdateExecutor);

                transitBoards.put(boardName, board);
            }

            return board;
        }
    }

    public void moveToTransit(String boardName)
    {
       synchronized (boards)
       {
           transitBoards.put(boardName, boards.remove(boardName));

           BulletinBoard board = new BulletinBoardImpl(boardName, transforms, boardUpdateExecutor);

           boards.put(boardName, board);
       }
    }

    public void markInTransit(String boardName)
    {
        synchronized (boards)
        {
            inTransitBoards.add(boardName);
            completedBoards.remove(boardName);
        }
    }

    public void markCompleted(String boardName)
    {
        synchronized (boards)
        {
            completedBoards.add(boardName);
            inTransitBoards.remove(boardName);
        }
    }

    public boolean isInTransit(String boardName)
    {
        synchronized (boards)
        {
            return inTransitBoards.contains(boardName);
        }
    }

    public boolean isComplete(String boardName)
    {
        synchronized (boards)
        {
            return completedBoards.contains(boardName);
        }
    }
}
