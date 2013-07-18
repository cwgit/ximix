package org.cryptoworkshop.ximix.mixnet.board;

/**
 *
 */
public interface BulletinBoardUploadListener
{
     void messagePosted(BulletinBoard runnable, int index, byte[] message);
}
