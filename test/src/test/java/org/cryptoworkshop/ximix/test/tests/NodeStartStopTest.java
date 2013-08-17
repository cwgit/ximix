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
package org.cryptoworkshop.ximix.test.tests;

import java.util.concurrent.TimeUnit;

import junit.framework.TestCase;
import org.cryptoworkshop.ximix.node.core.XimixNode;
import org.cryptoworkshop.ximix.test.node.NodeTestUtil;

/**
 * Tests for basic node stopping and starting.
 */
public class NodeStartStopTest
{


    /**
     * Tests that when stop is called the FutureComplete handler is called when the node shuts down completely.
     *
     * @throws Exception
     */
    @org.junit.Test
    public void testNodeStopWithFutureHandler()
        throws Exception
    {

        final XimixNode node = NodeTestUtil.getXimixNode("/conf/mixnet.xml", "/conf/node1.xml");


        Thread th = new Thread(new Runnable()
        {
            @Override
            public void run()
            {
                node.start();
            }
        });
        th.setPriority(Thread.MIN_PRIORITY);
        th.start();

        Thread.sleep(1000);
        TestCase.assertTrue(node.shutdown(15, TimeUnit.SECONDS));
    }


}
