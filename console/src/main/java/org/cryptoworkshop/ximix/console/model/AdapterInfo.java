package org.cryptoworkshop.ximix.console.model;

/**
 *
 */
public class AdapterInfo implements Comparable<AdapterInfo> {

    private String id = null;
    private String name = null;
    private String description = null;

    public AdapterInfo() {

    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
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

    @Override
    public int compareTo(AdapterInfo o) {
        return name.compareTo(o.getName());
    }
}
