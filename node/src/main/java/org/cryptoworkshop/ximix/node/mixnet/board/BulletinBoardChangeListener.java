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
 * Listener for objects that monitor board changes,
 */
public interface BulletinBoardChangeListener
{
    /**
     * Signal the addition of messages.
     *
     * @param bulletinBoard the board that had the messages added.
     * @param count the number of messages added.
     */
    void messagesAdded(BulletinBoard bulletinBoard, int count);

    /**
     * Signal the removal of messages.
     *
     * @param bulletinBoard the board that had the messages removed.
     * @param count the number of messages removed.
     */
    void messagesRemoved(BulletinBoardImpl bulletinBoard, int count);
}
