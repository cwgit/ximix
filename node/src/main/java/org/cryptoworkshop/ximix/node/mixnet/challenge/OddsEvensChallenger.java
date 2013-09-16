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
package org.cryptoworkshop.ximix.node.mixnet.challenge;

import org.cryptoworkshop.ximix.node.mixnet.util.IndexNumberGenerator;

/**
 * A base class for a challenger that swaps between odds and even ranges of messages.
 */
public abstract class OddsEvensChallenger
    implements IndexNumberGenerator
{
    protected final int stepNo;
    protected final  boolean isOddStepNumber;
    protected final int range;
    protected final boolean isOddRange;

    public OddsEvensChallenger(Integer size, Integer stepNo)
    {
        this.stepNo = stepNo;
        this.isOddStepNumber = ((stepNo.intValue() & 0x1) == 1);
        this.range = size / 2;
        this.isOddRange = ((size.intValue() & 0x1) == 1);
    }
}
