package org.cryptoworkshop.ximix.common.statistics;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.FutureTask;

/**
 *
 */
public class CrossSection
{
    private final Map<String, Object> values = new HashMap<>();
    private final Executor decoupler;


    public CrossSection(Executor decoupler)
    {
        super();
        this.decoupler = decoupler;
    }


    public Object get(String name, Object def)
    {
        if (!values.containsKey(name))
        {
            return def;
        }
        return values.get(name);
    }

    public void increment(final String name, final int step)
    {
        decoupler.execute(new Runnable()
        {
            @Override
            public void run()
            {
                Integer counter = (Integer)values.get(name);
                if (counter == null)
                {
                    counter = Integer.valueOf(step);
                }
                else
                {
                    counter += step;
                }

                values.put(name, counter);
            }
        });

    }

    public void increment(String name)
    {
        increment(name, 1);
    }


    public List getAsList(String name, boolean returnEmpty)
    {
        Object o = values.get(name);
        if (o != null && o instanceof List)
        {
            return (List)o;
        }
        else if (returnEmpty)
        {
            return Collections.EMPTY_LIST;
        }

        throw new IllegalArgumentException(name + " cannot be assigned to a List, it is " + o.getClass());
    }

    public Map<String, Object> getMap()
    {
        FutureTask<Map<String, Object>> task = new FutureTask(new Callable<Map<String, Object>>()
        {
            @Override
            public Map<String, Object> call()
                throws Exception
            {
                Map<String, Object> rv = new HashMap<String, Object>();

                rv.putAll(values);

                return Collections.unmodifiableMap(values);
            }
        });


        try
        {
            decoupler.execute(task);

            return task.get();
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
        }
        catch (ExecutionException e)
        {
            // TODO:
            e.printStackTrace();
        }

        return null;
    }
}
