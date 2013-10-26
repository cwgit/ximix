package org.cryptoworkshop.ximix.node.mixnet.test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import junit.framework.TestCase;
import org.cryptoworkshop.ximix.node.crypto.test.TestNotifier;
import org.cryptoworkshop.ximix.node.mixnet.board.BulletinBoard;
import org.cryptoworkshop.ximix.node.mixnet.board.BulletinBoardBackupListener;
import org.cryptoworkshop.ximix.node.mixnet.board.BulletinBoardImpl;
import org.junit.Test;

/**
 *
 */
public class BulletinBoardTest
    extends TestCase
{
    @Test
    public void testListener()
        throws Exception
    {
        BulletinBoard board = new BulletinBoardImpl("FRED", null, Executors.newSingleThreadExecutor(), new TestNotifier());
        final CountDownLatch uploadLatch = new CountDownLatch(2);
        final AtomicInteger clearCount = new AtomicInteger(0);
        final ArrayList<byte[]> messages = new ArrayList<>();

        for (int t = 0; t < uploadLatch.getCount(); t++)
        {
            messages.add(("Message "+t+" "+ System.currentTimeMillis()).getBytes());
        }

        board.addListener(new BulletinBoardBackupListener()
        {
            int t = 0;

            @Override
            public void cleared(BulletinBoard bulletinBoard)
            {
                clearCount.incrementAndGet();
            }

            @Override
            public void messagePosted(BulletinBoard bulletinBoard, int index, byte[] message)
            {
                TestCase.assertTrue(Arrays.equals(message, messages.get(t++)));
                uploadLatch.countDown();
            }

            @Override
            public void messagesPosted(BulletinBoard bulletinBoard, int startIndex, byte[][] messageBatch)
            {
                for (int i = 0; i != messageBatch.length; i++)
                {
                    TestCase.assertTrue(Arrays.equals(messageBatch[i], messages.get(t++)));
                    uploadLatch.countDown();
                }
            }
        });

        board.clear();

        for (byte[] msg: messages)
        {
            board.postMessage(msg);
        }

        TestCase.assertTrue("Latch failed.", uploadLatch.await(2, TimeUnit.SECONDS));
        TestCase.assertEquals(1, clearCount.get());
    }
}
