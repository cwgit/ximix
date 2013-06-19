package org.cryptoworkshop.ximix.console.nodeadapters;

import org.cryptoworkshop.ximix.common.console.annotations.CommandParam;
import org.cryptoworkshop.ximix.common.console.annotations.ConsoleCommand;
import org.cryptoworkshop.ximix.console.Main;
import org.cryptoworkshop.ximix.console.NodeAdapter;
import org.cryptoworkshop.ximix.console.handlers.messages.StandardMessage;
import org.cryptoworkshop.ximix.console.model.Command;
import org.cryptoworkshop.ximix.console.model.ParameterInfo;
import org.cryptoworkshop.ximix.console.util.Traversal;

import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 *
 */
public abstract class BaseNodeAdapter implements NodeAdapter {


    protected List<Command> commandList = new ArrayList<>();
    protected Map<Integer, Command> idToCommand = new ConcurrentHashMap<>();


    public BaseNodeAdapter() {

    }

    public StandardMessage invoke(int id, Map<String, String[]> params) {
        Command cmd = idToCommand.get(id);
        if (cmd == null) {
            return new StandardMessage(false, "Unknown command.");
        }

        Method m = cmd.getMethod();

        Class types[] = m.getParameterTypes();
        Object[] p = new Object[types.length];


        for (int t = 0; t < types.length; t++) {
            String[] v = params.get(String.valueOf(t));

            if (v == null) {
                return new StandardMessage(false, "Missing parameter " + t);
            }

            if (types[t].isArray()) {
                p[t] = v;
            } else {
                if (p.length == 0) {
                    return new StandardMessage(false, "Parameter sent but no value."); // Not sure this can happen.
                }
                p[t] = v[0];
            }
        }

        try {
            Object o = m.invoke(cmd.getInstance(), p);

            if (o instanceof StandardMessage) {
                return (StandardMessage) o;
            }

        } catch (Exception ex) {
            //TODO Ask about preferred logging framework.
            ex.printStackTrace();
            return new StandardMessage(false, "Unable to invoke method.");
        }


        return new StandardMessage(true, "Ok.");

    }

    public List<Command> getCommandList() {
        return commandList;
    }

    public void setCommandList(List<Command> commandList) {
        this.commandList = commandList;
    }

    protected void findCommands(Object... instances) throws Exception {
        for (Object o : instances) {

            Class cl = o.getClass();
            Method mm[] = cl.getMethods();
            for (Method m : mm) {

                ConsoleCommand cc = m.getAnnotation(ConsoleCommand.class);
                if (cc == null) {
                    continue;
                }

                Command command = new Command(Main.random().nextInt(), cc.name(), cc.description());
                command.setMethod(m);
                command.setInstance(o);
                commandList.add(command);
                idToCommand.put(command.getId(), command);

                Annotation[][] annotations = m.getParameterAnnotations();
                if (annotations == null || annotations.length < m.getParameterTypes().length) {
                    throw new IllegalArgumentException("Method  " + m.getName() + " in " + cl.getName() + " is missing parameter annotation.");
                }

                scanParameters(m, command.getParameters());


            }

        }

    }

    private void scanParameters(Object m, List<ParameterInfo> parameterList) throws Exception {

        Class[] types = null;
        Annotation[][] annotations = null;

        if (m instanceof Method) {
            types = ((Method) m).getParameterTypes();
            annotations = ((Method) m).getParameterAnnotations();

        } else if (m instanceof Constructor) {
            types = ((Constructor) m).getParameterTypes();
            annotations = ((Constructor) m).getParameterAnnotations();
        } else {
            throw new IllegalAccessException("m is not Method or Constructor.");
        }


        int t = 0;

        outer:
        for (Annotation[] aa : annotations) {
            Class type = types[t++];
            boolean array = false;
            for (Annotation a : aa) {
                if (a.annotationType() == CommandParam.class) {

                    if (type.isArray()) {
                        array = true;
                        type = type.getComponentType();
                    }

                    if (type.isPrimitive() || Number.class.isAssignableFrom(type) || String.class == type) {
                        ParameterInfo pinfo = new ParameterInfo(((CommandParam) a).name(), ((CommandParam) a).description());
                        pinfo.setVargs(array);
                        parameterList.add(pinfo);
                    } else {
                        //
                        // Some sort of object..
                        // In which case we will examine the constructors.
                        //

                        Constructor[] cons = type.getConstructors();
                        for (Constructor c : cons) {
                            if (c.isAnnotationPresent(CommandParam.class)) {
                                ParameterInfo info = new ParameterInfo(((CommandParam) a).name(), ((CommandParam) a).description());
                                info.setVargs(array);
                                info.addParameterInfo(null); // Establishes list.
                                parameterList.add(info);
                                scanParameters(c, info.getParameters());
                                continue outer;
                            }
                        }

                    }
                    continue outer;
                }
            }
            throw new IllegalArgumentException("Command parameter annotation missing.");
        }
    }


}
