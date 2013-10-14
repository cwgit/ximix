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


import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.cryptoworkshop.ximix.console.NodeAdapter;
import org.cryptoworkshop.ximix.console.config.AdapterConfig;
import org.cryptoworkshop.ximix.console.config.ConsoleConfig;
import org.cryptoworkshop.ximix.console.handlers.messages.StandardMessage;
import org.cryptoworkshop.ximix.console.model.Command;

/**
 *
 */
public abstract class BaseNodeAdapter
        implements NodeAdapter
{
    /**
     * List of commands that me be invoked by this adapter.
     */
    protected List<Command> commandList = new ArrayList<>();
    /**
     * Maps command id to command.
     */
    protected Map<Integer, Command> idToCommand = new ConcurrentHashMap<>();

    /**
     * Id of this adapter.
     */
    protected String id = null;
    /**
     * Name of this adapter.
     */
    protected String name = null;

    /**
     * Node description.
     */
    protected String description = null;

    /**
     * Connection has been established, opened.
     */
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
