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
package org.cryptoworkshop.ximix.console.model;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public class ParameterInfo
{
    String name = null;
    String description = null;
    int maxCount = 1;
    int minCount = 1;
    boolean vargs = false;
    List<ParameterInfo> parameters = null;


    public ParameterInfo()
    {

    }

    public ParameterInfo(String name, String description)
    {
        this.name = name;
        this.description = description;
    }

    public void addParameterInfo(ParameterInfo info)
    {
        if (parameters == null)
        {
            parameters = new ArrayList<>();
        }

        if (info == null)
        {
            return;
        }

        parameters.add(info);
    }


    public String getName()
    {
        return name;
    }

    public void setName(String name)
    {
        this.name = name;
    }

    public String getDescription()
    {
        return description;
    }

    public void setDescription(String description)
    {
        this.description = description;
    }

    public int getMaxCount()
    {
        return maxCount;
    }

    public void setMaxCount(int maxCount)
    {
        this.maxCount = maxCount;
    }

    public int getMinCount()
    {
        return minCount;
    }

    public void setMinCount(int minCount)
    {
        this.minCount = minCount;
    }

    public List<ParameterInfo> getParameters()
    {
        return parameters;
    }

    public void setParameters(List<ParameterInfo> parameters)
    {
        this.parameters = parameters;
    }

    public boolean isVargs()
    {
        return vargs;
    }

    public void setVargs(boolean vargs)
    {
        this.vargs = vargs;
    }
}
