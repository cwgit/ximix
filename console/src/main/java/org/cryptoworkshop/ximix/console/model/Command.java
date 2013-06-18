package org.cryptoworkshop.ximix.console.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.cryptoworkshop.ximix.console.NodeAdapter;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Defines a command that can be rendered and triggered on the console.
 */
public class Command {
    private long id = 0;
    private String title = null;
    private String description = null;
    private List<ParameterInfo> parameters = new ArrayList<>();

    @JsonIgnore
    private Method method = null;
    @JsonIgnore
    private NodeAdapter adapter = null;


    public Command(long id, String title, String description) {
        this.id = id;
        this.title = title;
        this.description = description;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<ParameterInfo> getParameters() {
        return parameters;
    }

    public void setParameters(List<ParameterInfo> parameters) {
        this.parameters = parameters;
    }

    public Method getMethod() {
        return method;
    }

    public void setMethod(Method method) {
        this.method = method;
    }

    public NodeAdapter getAdapter() {
        return adapter;
    }

    public void setAdapter(NodeAdapter adapter) {
        this.adapter = adapter;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Command command = (Command) o;

        if (id != command.id) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return (int) (id ^ (id >>> 32));
    }
}
