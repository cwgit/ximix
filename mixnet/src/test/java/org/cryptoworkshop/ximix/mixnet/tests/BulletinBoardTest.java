package org.cryptoworkshop.ximix.mixnet.tests;

import junit.framework.TestCase;
import org.cryptoworkshop.ximix.mixnet.board.BulletinBoard;
import org.cryptoworkshop.ximix.mixnet.board.BulletinBoardImpl;
import org.cryptoworkshop.ximix.mixnet.board.BulletinBoardUploadListener;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

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
        BulletinBoard board = new BulletinBoardImpl("FRED", null, Executors.newSingleThreadExecutor());
        final CountDownLatch latch = new CountDownLatch(2);
        final ArrayList<byte[]> messages = new ArrayList<>();

        for (int t = 0; t < latch.getCount(); t++)
        {
            messages.add(("Message "+t+" "+ System.currentTimeMillis()).getBytes());
        }

        board.addMessageUploadListener(new BulletinBoardUploadListener()
        {
            int t = 0;

            @Override
            public void messagePosted(BulletinBoard runnable, int index, byte[] message)
            {

                TestCase.assertTrue(Arrays.equals(message, messages.get(t++)));
                latch.countDown();
            }
        });

        for (byte[] msg: messages)
        {
            board.postMessage(msg);
        }


       Thread.sleep(1000);
        System.out.println(latch.getCount());



        //TestCase.assertTrue("Latch failed.",latch.await(2, TimeUnit.SECONDS));

    }
}
