package org.cryptoworkshop.ximix.console.adapters;

import org.cryptoworkshop.ximix.common.console.annotations.CommandParam;
import org.cryptoworkshop.ximix.common.console.annotations.ConsoleCommand;
import org.cryptoworkshop.ximix.console.Main;
import org.cryptoworkshop.ximix.console.NodeAdapter;
import org.cryptoworkshop.ximix.console.model.Command;
import org.cryptoworkshop.ximix.console.model.ParameterInfo;

import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public abstract class BaseNodeAdapter implements NodeAdapter {


   protected List<Command> commandList = new ArrayList<>();



    public BaseNodeAdapter() {

    }


    public List<Command> getCommandList() {
        return commandList;
    }

    public void setCommandList(List<Command> commandList) {
        this.commandList = commandList;
    }

    protected void findCommands(Class... classes) throws Exception {
        for (Class cl : classes) {


            Method mm[] = cl.getMethods();
            for (Method m : mm) {

                ConsoleCommand cc = m.getAnnotation(ConsoleCommand.class);
                if (cc == null)
                {
                    continue;
                }

                Command command = new Command(Main.random().nextLong(), cc.name(), cc.description());
                command.setMethod(m);
                command.setAdapter(this);
                commandList.add(command);

                Annotation[][] annotations = m.getParameterAnnotations();
                if (annotations == null || annotations.length < m.getParameterTypes().length)
                {
                    throw new IllegalArgumentException("Method  "+m.getName()+" in "+cl.getName()+" is missing parameter annotation.");
                }

                scanParameters(m, command.getParameters());

            }
        }

    }

    private void scanParameters(Object m, List<ParameterInfo> parameterList) throws Exception {

        Class[] types = null;
        Annotation[][] annotations = null;

        if (m instanceof Method)
        {
            types =  ((Method) m).getParameterTypes();
            annotations = ((Method)m).getParameterAnnotations();

        }   else if (m instanceof Constructor)
        {
            types =  ((Constructor) m).getParameterTypes();
            annotations = ((Constructor)m).getParameterAnnotations();
        }   else {
            throw new IllegalAccessException("m is not Method or Constructor.");
        }


        int t =0;

        outer: for (Annotation[] aa: annotations)
        {
            Class type = types[t++];
            for (Annotation a: aa)
            {
                if (a.annotationType() == CommandParam.class)
                {
                    if (type.isPrimitive() || Number.class.isAssignableFrom(type) || String.class == type)
                    {
                        ParameterInfo pinfo = new ParameterInfo(((CommandParam)a).name(),((CommandParam)a).description());

                        parameterList.add(pinfo);
                    }  else {
                        //
                        // Some sort of object..
                        // In which case we will examine the constructors.
                        //

                        Constructor[] cons = type.getConstructors();
                        for (Constructor c: cons)
                        {
                            if (c.isAnnotationPresent(CommandParam.class))
                            {
                                ParameterInfo info = new ParameterInfo(((CommandParam)a).name(),((CommandParam)a).description());
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
