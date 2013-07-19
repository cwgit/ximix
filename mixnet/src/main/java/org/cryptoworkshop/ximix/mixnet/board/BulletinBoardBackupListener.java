package org.cryptoworkshop.ximix.mixnet.board;

/**
 *
 */
public interface BulletinBoardBackupListener
{
     void cleared(BulletinBoard bulletinBoard);

     void messagePosted(BulletinBoard bulletinBoard, int index, byte[] message);
}
