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
package org.cryptoworkshop.ximix.node.service;

import org.cryptoworkshop.ximix.common.asn1.message.CapabilityMessage;
import org.cryptoworkshop.ximix.common.asn1.message.Message;
import org.cryptoworkshop.ximix.common.asn1.message.MessageReply;

/**
 * The basic interface for a node's service.
 */
public interface NodeService
{
    /**
     * Return a capability object describing this service.
     *
     * @return a description of the service's capabilities.
     */
    CapabilityMessage getCapability();

    /**
     * Pass in a message for this service to handle.
     *
     * @param message a message for processing.
     * @return a reply indicating success or failure and some associated data if appropriate.
     */
    MessageReply handle(Message message);

    /**
     * Return true if the passed in message can be handled by this service, false otherwise.
     *
     * @param message the message of interest.
     * @return true if meesage can be handled, false otherwise.
     */
    boolean isAbleToHandle(Message message);

    /**
     * Trigger a service to respond to a particular service event.
     *
     * @param event the event to be responded to.
     */
    void trigger(ServiceEvent event);

    /**
     * Add a listener for service statistics.
     *
     * @param statusListener the listener to be added.
     */
    void addListener(ServiceStatisticsListener statusListener);

    /**
     * Remove a listener from the service.
     *
     * @param serviceStatisticsListener the listener to be removed.
     */
    void removeListener(ServiceStatisticsListener serviceStatisticsListener);
}
