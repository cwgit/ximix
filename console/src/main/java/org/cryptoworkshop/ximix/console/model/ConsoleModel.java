package org.cryptoworkshop.ximix.console.model;

import org.cryptoworkshop.ximix.common.console.model.NodeInfo;
import org.cryptoworkshop.ximix.console.model.modeltypes.InMemoryModel;

import java.util.List;

/**
 * At this point this holds an in memory data model.
 */
public abstract class ConsoleModel {

    private static ConsoleModel model = new InMemoryModel();

    /**
     * Select the model type.
     *
     * @param type The type.
     */
    public static void useModelType(ModelType type) {
        switch (type) {
            case IN_MEMORY: {
                model = new InMemoryModel();
            }
            break;
        }
    }


    public static ConsoleModel model() {
        return model;
    }


    public abstract void addOrUpdate(NodeInfo info);

    public abstract List<NodeInfo> getNodeInfos();

}
