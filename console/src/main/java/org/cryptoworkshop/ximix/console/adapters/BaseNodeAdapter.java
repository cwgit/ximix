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
package org.cryptoworkshop.ximix.console.adapters;

import org.cryptoworkshop.ximix.common.console.annotations.CommandParam;
import org.cryptoworkshop.ximix.common.console.annotations.ConsoleCommand;
import org.cryptoworkshop.ximix.console.Main;
import org.cryptoworkshop.ximix.console.NodeAdapter;
import org.cryptoworkshop.ximix.console.config.AdapterConfig;
import org.cryptoworkshop.ximix.console.config.ConsoleConfig;
import org.cryptoworkshop.ximix.console.handlers.messages.StandardMessage;
import org.cryptoworkshop.ximix.console.model.Command;
import org.cryptoworkshop.ximix.console.model.ParameterInfo;
import org.cryptoworkshop.ximix.registrar.XimixRegistrarFactory;

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
public abstract class BaseNodeAdapter
        implements NodeAdapter
{
    protected List<Command> commandList = new ArrayList<>();
    protected Map<Integer, Command> idToCommand = new ConcurrentHashMap<>();
    protected String id = null;
    protected String name = null;
    protected String description = null;
    protected boolean opened = false;

    public BaseNodeAdapter()
    {

    }

    @Override
    public void init(ConsoleConfig consoleConfig, AdapterConfig config) throws Exception
    {
        id = config.getId();
        name = config.getName();
        description = config.getDescription();
    }

    @Override
    public String getCommandNameForId(int id)
    {
        Command cmd = idToCommand.get(id);

        if (cmd == null)
        {
            return "Unknown.";
        }

        return cmd.getMethod().getName();
    }

    @Override
    public StandardMessage invoke(int id, Map<String, String[]> params)
    {

        Command cmd = idToCommand.get(id);
        if (cmd == null)
        {
            return new StandardMessage(false, "Unknown command.");
        }

        Method m = cmd.getMethod();

        Class types[] = m.getParameterTypes();
        Object[] p = new Object[types.length];


        for (int t = 0; t < types.length; t++)
        {
            String[] v = params.get(String.valueOf(t));

            if (v == null)
            {
                return new StandardMessage(false, "Missing parameter " + t);
            }

            if (types[t].isArray())
            {
                p[t] = v;
            } else
            {
                if (p.length == 0)
                {
                    return new StandardMessage(false, "Parameter sent but no value."); // Not sure this can happen.
                }
                p[t] = v[0];
            }
        }

        try
        {
            //
            // Check it is open.
            //
            synchronized (this)
            {
                if (!opened)
                {
                    open();
                }
            }

            Object o = m.invoke(cmd.getInstance(), p);

            if (o instanceof StandardMessage)
            {
                return (StandardMessage) o;
            }

        } catch (Exception ex)
        {
            //TODO Ask about preferred logging framework.
            ex.printStackTrace();
            return new StandardMessage(false, "Exception occurred during call, see server log.");
        }


        return new StandardMessage(true, "Ok.");

    }

    @Override
    public List<Command> getCommandList()
    {
        return commandList;
    }

    public void setCommandList(List<Command> commandList)
    {
        this.commandList = commandList;
    }

    protected void findCommands(Object... instances)
            throws Exception
    {
        for (Object o : instances)
        {

            Class cl = o.getClass();
            Method mm[] = cl.getMethods();
            for (Method m : mm)
            {

                ConsoleCommand cc = m.getAnnotation(ConsoleCommand.class);
                if (cc == null)
                {
                    continue;
                }

                Command command = new Command(Main.random().nextInt(), cc.name(), cc.description());
                command.setMethod(m);
                command.setInstance(o);
                commandList.add(command);
                idToCommand.put(command.getId(), command);

                Annotation[][] annotations = m.getParameterAnnotations();
                if (annotations == null || annotations.length < m.getParameterTypes().length)
                {
                    throw new IllegalArgumentException("Method  " + m.getName() + " in " + cl.getName() + " is missing parameter annotation.");
                }

                scanParameters(m, command.getParameters());


            }

        }

    }

    private void scanParameters(Object m, List<ParameterInfo> parameterList)
            throws Exception
    {

        Class[] types = null;
        Annotation[][] annotations = null;

        if (m instanceof Method)
        {
            types = ((Method) m).getParameterTypes();
            annotations = ((Method) m).getParameterAnnotations();

        } else if (m instanceof Constructor)
        {
            types = ((Constructor) m).getParameterTypes();
            annotations = ((Constructor) m).getParameterAnnotations();
        } else
        {
            throw new IllegalAccessException("m is not Method or Constructor.");
        }


        int t = 0;

        outer:
        for (Annotation[] aa : annotations)
        {
            Class type = types[t++];
            boolean array = false;
            for (Annotation a : aa)
            {
                if (a.annotationType() == CommandParam.class)
                {

                    if (type.isArray())
                    {
                        array = true;
                        type = type.getComponentType();
                    }

                    if (type.isPrimitive() || Number.class.isAssignableFrom(type) || String.class == type)
                    {
                        ParameterInfo pinfo = new ParameterInfo(((CommandParam) a).name(), ((CommandParam) a).description());
                        pinfo.setVargs(array);
                        parameterList.add(pinfo);
                    } else
                    {
                        //
                        // Some sort of object..
                        // In which case we will examine the constructors.
                        //

                        Constructor[] cons = type.getConstructors();
                        for (Constructor c : cons)
                        {
                            if (c.isAnnotationPresent(CommandParam.class))
                            {
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

    public Map<Integer, Command> getIdToCommand()
    {
        return idToCommand;
    }

    public void setIdToCommand(Map<Integer, Command> idToCommand)
    {
        this.idToCommand = idToCommand;
    }

    @Override
    public String getId()
    {
        return id;
    }

    public void setId(String name)
    {
        this.id = name;
    }

    @Override
    public String getName()
    {
        return name;
    }

    public void setName(String name)
    {
        this.name = name;
    }

    @Override
    public String getDescription()
    {
        return description;
    }

    public void setDescription(String description)
    {
        this.description = description;
    }

    @Override
    public boolean isOpened()
    {
        return opened;
    }

    public void setOpened(boolean opened)
    {
        this.opened = opened;
    }

}
