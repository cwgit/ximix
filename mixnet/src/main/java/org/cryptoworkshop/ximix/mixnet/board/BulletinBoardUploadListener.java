package org.cryptoworkshop.ximix.mixnet.board;

/**
 *
 */
public interface BulletinBoardUploadListener
{
     void messagePosted(BulletinBoard bulletinBoard, int index, byte[] message);
}
