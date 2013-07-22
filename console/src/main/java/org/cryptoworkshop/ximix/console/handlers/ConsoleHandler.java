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
package org.cryptoworkshop.ximix.console.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.cryptoworkshop.ximix.console.NodeAdapter;
import org.cryptoworkshop.ximix.console.adapters.BaseNodeAdapter;
import org.cryptoworkshop.ximix.console.config.AdapterConfig;
import org.cryptoworkshop.ximix.console.config.ConsoleConfig;
import org.cryptoworkshop.ximix.console.handlers.messages.StandardMessage;
import org.cryptoworkshop.ximix.console.model.AdapterInfo;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;

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
    private Map<String, NodeAdapter> adapterMap = new HashMap<>();
    private ConsoleConfig consoleConfig = null;

    //    private MixnetCommandServiceAdapter mixnetCommandServiceAdapter = null;
    static
    {
        objectMapper.enable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
    }

    public ConsoleHandler(ConsoleConfig config)
        throws Exception
    {
        consoleConfig = config;

        for (AdapterConfig acfg : consoleConfig.getAdapters())
        {
            BaseNodeAdapter bna = (BaseNodeAdapter)Class.forName(acfg.getClassName()).newInstance();
            bna.init(consoleConfig, acfg);
            adapterMap.put(bna.getId(), bna);
        }


    }

    private NodeAdapter getAdapter(String lastPart)
    {
        NodeAdapter adapter = adapterMap.get(lastPart);

        synchronized (adapter)
        {
            if (!adapter.isOpened())
            {
                try
                {
                    adapter.open();
                }
                catch (Exception e)
                {
                    L.log(Level.SEVERE, "Unable to open adapter " + lastPart + " ", e);
                }
            }
        }

        return adapter;

    }

    @Override
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException
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
            NodeAdapter adapter = getAdapter(lastPart);
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

            NodeAdapter adapter = getAdapter(lastPart);
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

            NodeAdapter adapter = getAdapter(lastPart);
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
                    L.info(request.getRemoteAddr() + " Invoked Command method '" + adapter.getCommandNameForId(id) + " in " + adapter.getId() + " (" + adapter.getClass().getName() + ")" + "' with " + request.getParameterMap());
                }
                catch (Exception nfe)
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

    private void writeObject(Object o, HttpServletResponse resp)
        throws IOException
    {
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setContentType("application/json");
        OutputStream os = resp.getOutputStream();
        objectMapper.writeValue(os, o);
        os.flush();
        os.close();
    }
}
