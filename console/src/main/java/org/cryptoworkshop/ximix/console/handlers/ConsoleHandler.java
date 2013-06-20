package org.cryptoworkshop.ximix.console.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.cryptoworkshop.ximix.common.conf.Config;
import org.cryptoworkshop.ximix.common.conf.ConfigException;
import org.cryptoworkshop.ximix.console.NodeAdapter;
import org.cryptoworkshop.ximix.console.handlers.messages.StandardMessage;
import org.cryptoworkshop.ximix.console.model.AdapterInfo;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 */
public class ConsoleHandler extends AbstractHandler
{

    private static Logger L = Logger.getLogger("Console");
    private static ObjectMapper objectMapper = new ObjectMapper();
    Map<String, NodeAdapter> adapterMap = new HashMap<>();

    //    private MixnetCommandServiceAdapter mixnetCommandServiceAdapter = null;
    static
    {
        objectMapper.enable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
    }

    public ConsoleHandler(Config config) throws Exception
    {

        try
        {

            NodeList lst = config.getNodeList("adapters");
            for (int t = 0; t < lst.getLength(); t++)
            {
                Node n = lst.item(t);

                if ("adapter".equals(n.getNodeName()))
                {

                    NodeList nl = n.getChildNodes();

                    String cl = Config.getValueOf(nl,"class");
                    if (cl != null)
                    {
                        NodeAdapter na = (NodeAdapter)Class.forName(cl).newInstance();
                        na.init(config,n);

                        adapterMap.put(na.getId(),na);
                    }


                }
            }


//            StringTokenizer toke = new StringTokenizer(Config.config().getProperty("console.adapters"), ",");
//            while (toke.hasMoreTokens()) {
//                String name = toke.nextToken().trim();
//                if (name.length() == 0) {
//                    continue;
//                }
//
//                try {
//                    Class cl = Class.forName(Config.config().getProperty(name + ".adapter"));
//
//                    NodeAdapter adapter = (NodeAdapter) cl.newInstance();
//                    adapter.init(name, Config.getAdapterSubset(name));
//                    //      adapter.open(); // TODO this needs to happen as part of some sort of user initiated connect phase..
//                    adapterMap.put(name, adapter);
//
//                } catch (Exception ex) {
//                    L.log(Level.SEVERE, "Initializing adapter " + name, ex);
//                    throw new RuntimeException("Unable to instantiate adapter class " + name, ex);
//                }
//
//            }


//            mixnetCommandServiceAdapter = new MixnetCommandServiceAdapter();
//
//
//            mixnetCommandServiceAdapter.init(null);       // TODO Discuss unified configuration across system.
            //mixnetCommandServiceAdapter.open();

        } catch (Exception e)
        {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
    }

    @Override
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
    {

        String reqUri = request.getRequestURI();
        String lastPart = null;
        int a = reqUri.lastIndexOf('/');
        if (a > -1 && a + 1 < reqUri.length())
        {
            lastPart = reqUri.substring(a + 1);
        }

        if ("/api/adapters".equals(reqUri))
        {
            ArrayList<AdapterInfo> out = new ArrayList<>();
            Iterator<Map.Entry<String, NodeAdapter>> it = adapterMap.entrySet().iterator();
            while (it.hasNext())
            {
                out.add((it.next().getValue()).getInfo());
            }
            Collections.sort(out);
            writeObject(out, response);
            baseRequest.setHandled(true);
            return;
        }


        if (reqUri.startsWith("/api/nodes"))
        {
            response.setContentType("application/json");
            NodeAdapter adapter = adapterMap.get(lastPart);
            if (adapter == null)
            {
                writeObject(new StandardMessage(false, "Unknown adapter."), response);
                baseRequest.setHandled(true);
                return;
            }

            writeObject(adapter.getNodeInfo(), response);
            baseRequest.setHandled(true);
            return;

        }


        if (reqUri.startsWith("/api/commands"))
        {
            response.setContentType("application/json");

            NodeAdapter adapter = adapterMap.get(lastPart);
            if (adapter == null)
            {
                writeObject(new StandardMessage(false, "Unknown adapter."), response);
                baseRequest.setHandled(true);
                return;
            }


            writeObject(adapter.getCommandList(), response);
            baseRequest.setHandled(true);
            return;
        }

        if (reqUri.startsWith("/api/invoke"))
        {

            NodeAdapter adapter = adapterMap.get(lastPart);
            if (adapter == null)
            {
                writeObject(new StandardMessage(false, "Unknown adapter."), response);
                baseRequest.setHandled(true);
                return;
            }


            StandardMessage ret = new StandardMessage(false, "Invalid command.");

            String cmd = request.getParameter("cmd");
            if (cmd != null)
            {


                try
                {
                    int id = Integer.valueOf(cmd);
                    ret = adapter.invoke(id, request.getParameterMap());
                    L.info(request.getRemoteAddr() + " Invoked Command method '" + adapter.getCommandNameForId(id)+" in "+ adapter.getId() + " ("+adapter.getClass().getName()+")"+  "' with " + request.getParameterMap());
                } catch (Exception nfe)
                {
                    L.log(Level.WARNING, "Invalid command " + cmd, nfe);
                }
            }

            response.setContentType("application/json");
            writeObject(ret, response);
            baseRequest.setHandled(true);
            return;
        }


        System.out.println(request.getRequestURI());
        response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        response.setContentType("text/plain");
        response.getOutputStream().write("Unknown call.".getBytes(Charset.defaultCharset()));
        baseRequest.setHandled(true);
    }

    private void writeObject(Object o, HttpServletResponse resp) throws IOException
    {
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setContentType("application/json");
        OutputStream os = resp.getOutputStream();
        objectMapper.writeValue(os, o);
        os.flush();
        os.close();
    }
}
