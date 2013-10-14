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
import org.cryptoworkshop.ximix.common.asn1.message.TranscriptBlock;
import org.cryptoworkshop.ximix.common.util.ListenerHandler;
import org.cryptoworkshop.ximix.common.util.TranscriptType;
import org.cryptoworkshop.ximix.node.mixnet.util.IndexNumberGenerator;

/**
 * Basic interface for a bulletin board.
 */
public interface BulletinBoard
    extends Iterable<PostedMessage>
{
    /**
     * Transcript witness data set name.
     */
    String WITNESSES = "witnesses";

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
     * Return the number of messages in the board transcript. The return value
     * of this method is only meaningful after a shuffle operation has been completed.
     *
     * @return size of the board transcript for the given type.
     */
    int transcriptSize(TranscriptType transcriptType);

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

    /**
     * Post a block of witnesses to the board's private data.
     *
     * @param witnessBlock the witnesses to be posted.
     */
    void postWitnessBlock(final MessageWitnessBlock witnessBlock);

    /**
     * Clear all the messages from the board.
     */
    void clear();

    /**
     * Add a backup listener to the board.
     *
     * @param bulletinBoardBackupListener the backup listener to add.
     */
    void addListener(BulletinBoardBackupListener bulletinBoardBackupListener);

    /**
     * Shutdown the board.
     */
    void shutdown();

    /**
     * Return the handler for the passed in listener class.
     *
     * @param listenerClass the interface class of listeners of the handler of interest.
     * @param <T> the type of the interface.
     * @return the associated ListenerHandler.
     * @exception IllegalStateException if the listener is not valid.
     */
    <T> ListenerHandler<T> getListenerHandler(Class<T> listenerClass);

    /**
     * Add a change listener to the board.
     *
     * @param listener the change listener to add.
     */
    void addListener(BulletinBoardChangeListener listener);

    /**
     * Fetch a block of transcript information.
     *
     * @param dataClass the type of transcript information.
     * @param indexGenerator the source of index numbers to be downloaded.
     * @param responseBuilder the builder for creating the response carrying the data.
     * @return a block of transcript data of the appropriate type.
     */
    TranscriptBlock fetchTranscriptData(TranscriptType dataClass, IndexNumberGenerator indexGenerator, TranscriptBlock.Builder responseBuilder);
}
