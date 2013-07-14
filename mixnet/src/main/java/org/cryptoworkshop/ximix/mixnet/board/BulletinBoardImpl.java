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

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.FutureTask;

public class BulletinBoardImpl
    implements BulletinBoard
{
    private final String boardName;
    private final Executor boardUpdateExecutor;
    private final File workingFile;

    private List<byte[]> messages = new ArrayList<>();

    public BulletinBoardImpl(String boardName, File workingDirectory, Executor executor)
    {
        this.boardName = boardName;
        this.boardUpdateExecutor = executor;

        if (workingDirectory != null)
        {
            this.workingFile = new File(workingDirectory, boardName);
            if (this.workingFile.exists())
            {
                // TODO: this might be better scheduled... on the other hand maybe not.

                int len = 0;

                try
                {
                    DataInputStream dIn = new DataInputStream(new BufferedInputStream(new FileInputStream(this.workingFile)));

                    for (;;)
                    {
                        len = dIn.readInt();
                        byte[] data = new byte[len];

                        dIn.readFully(data);

                        messages.add(data);

                        len = 0;
                    }
                }
                catch (EOFException e)
                {
                    if (len != 0)
                    {
                        // TODO: we've truncated
                    }
                    // we're done!
                }
                catch (IOException e)
                {
                    // TODO: log error!
                }

            }
        }
        else
        {
            workingFile = null;
        }
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
                messages.add(message);

                if (workingFile != null)
                {
                    try
                    {
                        ByteArrayOutputStream bOut = new ByteArrayOutputStream(4 + message.length);
                        DataOutputStream dOut = new DataOutputStream(bOut);

                        dOut.writeInt(message.length);
                        dOut.write(message);
                        dOut.close();

                        FileOutputStream fOut = new FileOutputStream(workingFile, true);

                        fOut.write(bOut.toByteArray());

                        fOut.close();
                    }
                    catch (IOException e)
                    {
                        // TODO:
                        e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                    }
                }
            }
        });
    }

    @Override
    public List<byte[]> getMessages(final int maxNumberOfMessages)
    {
        FutureTask<List<byte[]>> task = new FutureTask<>(new Callable<List<byte[]>>()
        {
            @Override
            public List<byte[]> call()
                throws Exception
            {
                int count;

                if (messages.size() > maxNumberOfMessages)
                {
                    count = maxNumberOfMessages;
                }
                else
                {
                    count = messages.size();
                }

                List<byte[]> rv = new ArrayList<>(count);

                for (int i = 0; i != count; i++)
                {
                    rv.add(messages.remove(0));
                }

                return rv;
            }
        });

        boardUpdateExecutor.execute(task);

        try
        {
            return task.get();
        }
        catch (InterruptedException e)
        {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
        catch (ExecutionException e)
        {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
        return null; // TODO:
    }

    @Override
    public void clear()
    {
        boardUpdateExecutor.execute(new Runnable()
        {
            public void run()
            {
                messages.clear();
                if (workingFile != null)
                {
                    try
                    {
                        FileOutputStream fOut = new FileOutputStream(workingFile);

                        fOut.write(new byte[0]);

                        fOut.close();
                    }
                    catch (IOException e)
                    {
                        // TODO
                        e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                    }
                }
            }
        });
    }

    @Override
    public File getFile()
    {
        return workingFile;
    }

    public Iterator<byte[]> iterator()
    {
        FutureTask<Iterator<byte[]>> task = new FutureTask<>(new Callable<Iterator<byte[]>>()
        {
            @Override
            public Iterator<byte[]> call()
                throws Exception
            {
                return new ArrayList<byte[]>(messages).iterator();
            }
        });

        boardUpdateExecutor.execute(task);

        try
        {
            return task.get();
        }
        catch (InterruptedException e)
        {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
        catch (ExecutionException e)
        {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }

        return null; // TODO:
    }
}
