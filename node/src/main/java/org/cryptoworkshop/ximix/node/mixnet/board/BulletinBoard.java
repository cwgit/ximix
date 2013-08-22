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

import org.cryptoworkshop.ximix.common.asn1.message.MessageWitnessBlock;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessage;
import org.cryptoworkshop.ximix.common.asn1.message.PostedMessageBlock;
import org.cryptoworkshop.ximix.common.util.ListenerHandler;

/**
 * Basic interface for a bulletin board.
 */
public interface BulletinBoard
    extends Iterable<PostedMessage>
{
    /**
     * Return the name of the board.
     *
     * @return the board name.
     */
    String getName();

    /**
     * Return the number of messages on the board.
     *
     * @return current message count.
     */
    int size();

    /**
     * Post a message to the end of the board.
     *
     * @param message message to be posted.
     */
    void postMessage(final byte[] message);

    /**
     * Replace or add a block of messages by index.
     *
     * @param messageBlock the block of messages to be added/replaced.
     */
    void postMessageBlock(final PostedMessageBlock messageBlock);

    /**
     * Remove a block of messages from the start of the message list.
     *
     * @param blockBuilder the builder to construct the messages block with.
     *
     * @return a block of messages.
     */
    PostedMessageBlock removeMessages(PostedMessageBlock.Builder blockBuilder);

    void postWitnessBlock(final MessageWitnessBlock witnessBlock);

    /**
     * Clear all the messages from the board.
     */
    void clear();

    void addListener(BulletinBoardBackupListener bulletinBoardBackupListener);

    void shutdown();

    <T> ListenerHandler<T> getListenerHandler(Class<T> listenerClass);

    void addListener(BulletinBoardChangeListener listener);
}
