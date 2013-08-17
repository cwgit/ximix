package org.cryptoworkshop.ximix.node.mixnet.board;

/**
 *
 */
public interface BulletinBoardBackupListener
{
     void cleared(BulletinBoard bulletinBoard);

     void messagePosted(BulletinBoard bulletinBoard, int index, byte[] message);
}
