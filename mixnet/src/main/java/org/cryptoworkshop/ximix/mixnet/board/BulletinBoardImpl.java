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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Executor;

public class BulletinBoardImpl
    implements BulletinBoard
{
    private final String boardName;
    private final Executor boardUpdateExecutor;

    private List<byte[]> messages = new ArrayList<byte[]>();

    public BulletinBoardImpl(String boardName, Executor executor)
    {
        this.boardName = boardName;
        this.boardUpdateExecutor = executor;
    }

    public String getName()
    {
        return boardName;
    }

    public void postMessage(final byte[] message)
    {
        boardUpdateExecutor.execute(new Runnable()
        {
            public void run()
            {
                System.err.println("message posted");

                messages.add(message);
            }
        });
    }

    public Iterator<byte[]> iterator()
    {
        return messages.iterator();
    }
}
