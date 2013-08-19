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
package org.cryptoworkshop.ximix.client.connection;

import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.MessageType;

/**
 * Basic interface for privileged service connections.
 */
public interface AdminServicesConnection
    extends ServicesConnection
{
    /**
     * Return the current set of active nodes behind this connection.
     *
     * @return the set of active nodes.
     */
    Set<String> getActiveNodeNames();

    /**
     * Send a message to a specific node.
     *
     * @param nodeName node message is to be sent to.
     * @param type type of the message.
     * @param messagePayload the data making up the message payload.
     * @return a reply indicating message acceptance or rejection.
     * @throws ServiceConnectionException in case of network failure.
     */
    MessageReply sendMessage(String nodeName, MessageType type, ASN1Encodable messagePayload)
        throws ServiceConnectionException;
}
