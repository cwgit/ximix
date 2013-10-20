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
package org.cryptoworkshop.ximix.node.mixnet.board;

/**
 * Listener for objects that back up board data.
 */
public interface BulletinBoardBackupListener
{
    /**
     * Signal a board has been cleared.
     *
     * @param bulletinBoard the board that was cleared.
     */
    void cleared(BulletinBoard bulletinBoard);

    /**
     * Signal a board has had a message posted to it.
     *
     * @param bulletinBoard the board that received the messages.
     * @param index         the index the message was posted at.
     * @param message       the data representing the message posted.
     */
    void messagePosted(BulletinBoard bulletinBoard, int index, byte[] message);

    /**
     * Signal a board has had a batch of messages posted to it.
     *
     * @param bulletinBoard the board that received the messages.
     * @param startIndex    the index the first message in the batch was posted at.
     * @param messages      the data representing the message batch posted.
     */
    void messagesPosted(BulletinBoard bulletinBoard, int startIndex, byte[][] messages);
}
