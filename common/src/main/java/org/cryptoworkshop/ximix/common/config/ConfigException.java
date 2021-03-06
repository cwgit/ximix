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
package org.cryptoworkshop.ximix.common.config;

/**
 * Base configuration exception.
 */
public class ConfigException
    extends Exception
{
    /**
     * Constructor for an exception with an underlying cause.
     *
     * @param message the message associated with the exception.
     * @param cause the throwable causing this exception..
     */
    public ConfigException(String message, Throwable cause)
    {
        super(message, cause);
    }

    /**
     * Basic constructor - a simple message,
     *
     * @param message
     */
    public ConfigException(String message)
    {
        super(message);
    }
}
