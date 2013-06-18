package org.cryptoworkshop.ximix.console.model;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public class ParameterInfo {
    String name = null;
    String description = null;
    int maxCount = 1;
    int minCount = 1;
    boolean vargs =false;
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

        if (info == null) {return;}

        parameters.add(info);
    }


    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public int getMaxCount() {
        return maxCount;
    }

    public void setMaxCount(int maxCount) {
        this.maxCount = maxCount;
    }

    public int getMinCount() {
        return minCount;
    }

    public void setMinCount(int minCount) {
        this.minCount = minCount;
    }

    public List<ParameterInfo> getParameters() {
        return parameters;
    }

    public void setParameters(List<ParameterInfo> parameters) {
        this.parameters = parameters;
    }

    public boolean isVargs() {
        return vargs;
    }

    public void setVargs(boolean vargs) {
        this.vargs = vargs;
    }
}
