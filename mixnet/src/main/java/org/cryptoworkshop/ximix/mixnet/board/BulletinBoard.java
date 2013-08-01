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
package org.cryptoworkshop.ximix.mixnet.board;

import org.cryptoworkshop.ximix.common.message.PostedMessage;
import org.cryptoworkshop.ximix.common.message.PostedMessageBlock;
import org.cryptoworkshop.ximix.common.util.ListenerHandler;

public interface BulletinBoard
    extends Iterable<PostedMessage>
{
    String getName();

    int size();

    void postMessage(final byte[] message);

    void postMessageBlock(final PostedMessageBlock messageBlock);

    PostedMessageBlock getMessages(PostedMessageBlock.Builder blockBuilder);

    void clear();

    void addListener(BulletinBoardBackupListener bulletinBoardBackupListener);

    void shutdown();

    <T> ListenerHandler<T> getListenerHandler(Class<T> listenerClass);

    void addListener(BulletinBoardChangeListener listener);
}
