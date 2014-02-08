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

import org.bouncycastle.asn1.ASN1Encodable;
import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;
import org.cryptoworkshop.ximix.common.asn1.message.MessageType;
import org.cryptoworkshop.ximix.common.util.EventNotifier;

/**
 * Basic interface for a connection.
 */
public interface ServicesConnection
{
    /**
     * Do initial activation of the connection
     */
    void activate()
        throws ServiceConnectionException;

    /**
     * Return the capability set represented by the network nodes behind this connection.
     *
     * @return an array of capabilities.
     */
    CapabilityMessage[] getCapabilities()
        throws ServiceConnectionException;

    /**
     * Return the event notifier to use for problems or info messages on this connection.
     * @return an EventNotifier
     */
    EventNotifier getEventNotifier();

    /**
     * Send a message to the Ximix network.
     *
     * @param type message type
     * @param messagePayload data making up the message payload.
     * @return a  reply indicating message acceptance or rejection.
     * @throws ServiceConnectionException
     */
    MessageReply sendMessage(MessageType type, ASN1Encodable messagePayload)
        throws ServiceConnectionException;

    /**
     * Close the underlying Ximix connection.
     *
     * @throws ServiceConnectionException in case of failure to shutdown cleanly.
     */
    void shutdown() throws ServiceConnectionException;
}
