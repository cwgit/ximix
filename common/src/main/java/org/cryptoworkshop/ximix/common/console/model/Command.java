package org.cryptoworkshop.ximix.common.console.model;

import java.util.HashMap;
import java.util.Map;

/**
 *  Defines a command that can be rendered and triggered on the console.
 */
public class Command {
    private String id = null;
    private String title = null;
    private String description = null;
    private Map<String, String> propertyIdToTitle = new HashMap<>();


    public Command(String id, String title, String description) {
        this.id = id;
        this.title = title;
        this.description = description;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Command command = (Command) o;

        if (!id.equals(command.id)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }
}
