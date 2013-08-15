package org.cryptoworkshop.ximix.demo.lt;

import org.cryptoworkshop.ximix.common.config.Config;

import java.io.File;

/**
 *
 */
public class LoadTester
{
    public static void main(String[] args)
        throws Exception
    {
        Config config = new Config(new File(args[0]));
        LoadTesterConfig cfg = (LoadTesterConfig)config.getConfigObjects("lt",new LoadTesterConfigFactory());



    }


}
