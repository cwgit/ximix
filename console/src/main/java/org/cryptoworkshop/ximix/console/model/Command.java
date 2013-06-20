package org.cryptoworkshop.ximix.console.model;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * Defines a command that can be rendered and triggered on the console.
 */
public class Command
{
    private int id = 0;
    private String title = null;
    private String description = null;
    private List<ParameterInfo> parameters = new ArrayList<>();

    @JsonIgnore
    private Method method = null;
    @JsonIgnore
    private Object instance = null;


    public Command(int id, String title, String description)
    {
        this.id = id;
        this.title = title;
        this.description = description;
    }

    public int getId()
    {
        return id;
    }

    public void setId(int id)
    {
        this.id = id;
    }

    public String getTitle()
    {
        return title;
    }

    public void setTitle(String title)
    {
        this.title = title;
    }

    public String getDescription()
    {
        return description;
    }

    public void setDescription(String description)
    {
        this.description = description;
    }

    public List<ParameterInfo> getParameters()
    {
        return parameters;
    }

    public void setParameters(List<ParameterInfo> parameters)
    {
        this.parameters = parameters;
    }

    public Method getMethod()
    {
        return method;
    }

    public void setMethod(Method method)
    {
        this.method = method;
    }

    public Object getInstance()
    {
        return instance;
    }

    public void setInstance(Object instance)
    {
        this.instance = instance;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Command command = (Command) o;

        if (id != command.id) return false;

        return true;
    }

    @Override
    public int hashCode()
    {
        return id;
    }
}
