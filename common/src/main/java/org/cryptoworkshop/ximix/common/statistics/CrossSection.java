package org.cryptoworkshop.ximix.common.statistics;

import org.cryptoworkshop.ximix.common.handlers.EventNotifier;

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
    private final Map<String, Object> placeholders = new HashMap<>();
    private final Executor decoupler;
    private final EventNotifier eventNotifier;


    public CrossSection(Executor decoupler, EventNotifier eventNotifier)
    {
        super();
        this.decoupler = decoupler;
        this.eventNotifier = eventNotifier;
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

    public void decrement(String name)
    {
        increment(name, -1);
    }

    public void decrement(String name, int value)
    {
        increment(name, (Math.abs(value) * -1));
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

                return Collections.unmodifiableMap(rv);
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
            eventNotifier.notify(EventNotifier.Level.ERROR, "Forming crosssection: " + e.getMessage(), e);
        }

        return null;
    }


    public void addPlaceholderValue(final String name, final Object value)
    {
        decoupler.execute(new Runnable()
        {
            @Override
            public void run()
            {
                placeholders.put(name, value);
            }
        });
    }


    public void ensurePlaceholders()
    {
        decoupler.execute(new Runnable()
        {
            @Override
            public void run()
            {
                values.putAll(placeholders);
            }
        });
    }


}
