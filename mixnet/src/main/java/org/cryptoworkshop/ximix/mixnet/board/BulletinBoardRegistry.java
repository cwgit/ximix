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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executor;

import org.cryptoworkshop.ximix.common.service.Decoupler;
import org.cryptoworkshop.ximix.common.service.NodeContext;
import org.cryptoworkshop.ximix.common.util.ListenerHandler;
import org.cryptoworkshop.ximix.mixnet.transform.Transform;

public class BulletinBoardRegistry
{
    private final NodeContext nodeContext;
    private final File workingDirectory;
    private final Map<String, Transform> transforms;
    private final Executor boardUpdateExecutor;
    private final BulletinBoardChangeListener changeListener;

    private Map<String, BulletinBoard> boards = new HashMap<>();
    private Map<String, BulletinBoard> transitBoards = new HashMap<String, BulletinBoard>();
    private Map<String, BulletinBoard> backupBoards = new HashMap<String, BulletinBoard>();
    private Set<String> suspendedBoards = new HashSet<>();
    private Set<String> dowloadLockedBoards = new HashSet<>();
    private Set<String> shuffleLockedBoards = new HashSet<>();
    private Set<String> inTransitBoards = new HashSet<>();
    private Set<String> completedBoards = new HashSet<>();


    public BulletinBoardRegistry(NodeContext nodeContext, Map<String, Transform> transforms, BulletinBoardChangeListener changeListener)
    {
        this.nodeContext = nodeContext;
        this.transforms = transforms;
        this.boardUpdateExecutor = nodeContext.getDecoupler(Decoupler.BOARD_REGISTRY);
        this.changeListener = changeListener;

        File homeDirectory = nodeContext.getHomeDirectory();

        if (homeDirectory != null)
        {
            this.workingDirectory = new File(homeDirectory, "boards");
            if (!this.workingDirectory.exists())
            {
                if (!workingDirectory.mkdir())
                {
                    // TODO:
                }
            }
        }
        else
        {
            workingDirectory = null;
        }
    }

    public BulletinBoard createBoard(final String boardName)
    {
        synchronized (boards)
        {
            BulletinBoard board = boards.get(boardName);

            // TODO: need to detect twice!
            if (board == null)
            {
                File boardDBFile = deriveBoardFile(boardName);

                board = new BulletinBoardImpl(boardName, boardDBFile, nodeContext.getScheduledExecutor());
                board.addListener(changeListener);

                boards.put(boardName, board);
            }

            return board;
        }
    }

    /**
     * Returns a null board file if the workingDirectory is not specified.
     * It assumes that if no workingDirectory is specified there was no intention
     * to persist data.
     *
     * @param boardName
     * @return
     */
    private File deriveBoardFile(String boardName)
    {
        if (workingDirectory != null)
        {
            return new File(workingDirectory, boardName);
        }

        return null;
    }

    public BulletinBoard getBoard(final String boardName)
    {
        synchronized (boards)
        {
            return boards.get(boardName);
        }
    }

    public String[] getBoardNames()
    {
        synchronized (boards)
        {
            return boards.keySet().toArray(new String[boards.size()]);
        }
    }

    public Transform[] getTransforms()
    {
        return transforms.values().toArray(new Transform[transforms.size()]);
    }

    public Transform getTransform(String transformName)
    {
        return transforms.get(transformName);
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

    public BulletinBoard getBackupBoard(String boardName)
    {
        synchronized (boards)
        {
            BulletinBoard board = backupBoards.get(boardName);

            // TODO: need to detect twice!
            if (board == null)
            {
                board = new BulletinBoardImpl(boardName, deriveBoardFile(boardName + ".backup"), boardUpdateExecutor);

                backupBoards.put(boardName, board);
            }

            return board;
        }
    }

    public BulletinBoard getTransitBoard(long operationNumber, String boardName, int stepNumber)
    {
        synchronized (boards)
        {
            String transitBoardName = getTransitBoardName(operationNumber, boardName, stepNumber);
            BulletinBoard board = transitBoards.get(transitBoardName);

            // TODO: need to detect twice!
            if (board == null)
            {
                board = new BulletinBoardImpl(boardName, deriveBoardFile(transitBoardName), boardUpdateExecutor);

                transitBoards.put(boardName, board);
            }

            return board;
        }
    }

    public void moveToTransit(long operationNumber, String boardName, int stepNumber)
    {
        synchronized (boards)
        {
            BulletinBoard originalBoard = boards.remove(boardName);

            ListenerHandler<BulletinBoardBackupListener> listenerHandler = originalBoard.getListenerHandler(BulletinBoardBackupListener.class);
            ListenerHandler<BulletinBoardChangeListener> changeHandler = originalBoard.getListenerHandler(BulletinBoardChangeListener.class);

            if (workingDirectory != null)
            {
                originalBoard.shutdown();

                File workingFile = deriveBoardFile(originalBoard.getName());
                File dotPFile = deriveBoardFile(originalBoard.getName() + ".p");
                File transitWorkingFile = deriveBoardFile(getTransitBoardName(operationNumber, originalBoard.getName(), stepNumber));
                File transitDotPFile = deriveBoardFile(getTransitBoardName(operationNumber, originalBoard.getName(), stepNumber) + ".p");

                if (!workingFile.renameTo(transitWorkingFile))
                {
                    System.err.println("rename failed!!!! " + workingFile.getPath() + " " + transitWorkingFile);
                    // TODO:
                }

                if (!dotPFile.renameTo(transitDotPFile))
                {
                    System.err.println("rename failed!!!! " + workingFile.getPath() + " " + transitWorkingFile);
                    // TODO:
                }

                originalBoard = new BulletinBoardImpl(originalBoard.getName(), transitWorkingFile, nodeContext.getScheduledExecutor());
            }

            transitBoards.put(getTransitBoardName(operationNumber, boardName, stepNumber), originalBoard);

            BulletinBoard board = new BulletinBoardImpl(boardName, deriveBoardFile(boardName), listenerHandler, changeHandler);
            board.addListener(changeListener);
            boards.put(boardName, board);
        }
    }

    public void markInTransit(long operationNumber, String boardName, int stepNumber)
    {
        synchronized (boards)
        {
            String transitName = getTransitBoardName(operationNumber, boardName, stepNumber);

            inTransitBoards.add(transitName);
            completedBoards.remove(transitName);
        }
    }

    public void markCompleted(long operationNumber, String boardName, int stepNumber)
    {
        synchronized (boards)
        {
            String transitName = getTransitBoardName(operationNumber, boardName, stepNumber);

            completedBoards.add(transitName);
            inTransitBoards.remove(transitName);
        }
    }

    public boolean isInTransit(long operationNumber, String boardName, int stepNumber)
    {
        synchronized (boards)
        {
            String transitName = getTransitBoardName(operationNumber, boardName, stepNumber);

            return inTransitBoards.contains(transitName);
        }
    }

    public boolean isComplete(long operationNumber, String boardName, int stepNumber)
    {
        synchronized (boards)
        {
            String transitName = getTransitBoardName(operationNumber, boardName, stepNumber);

            return completedBoards.contains(transitName);
        }
    }

    private String getTransitBoardName(long operationNumber, String boardName, int stepNumber)
    {
        return operationNumber + "." + boardName + "." + stepNumber;
    }
}
