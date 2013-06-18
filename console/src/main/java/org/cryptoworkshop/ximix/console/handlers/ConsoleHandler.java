package org.cryptoworkshop.ximix.console.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.cryptoworkshop.ximix.console.model.Command;
import org.cryptoworkshop.ximix.console.nodeadapters.MixnetCommandServiceAdapter;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;

/**
 *
 */
public class ConsoleHandler extends AbstractHandler {

    private static ObjectMapper objectMapper = new ObjectMapper();
    private MixnetCommandServiceAdapter mixnetCommandServiceAdapter = null;


    static {
        objectMapper.enable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
    }

    public ConsoleHandler() {

        try {
           mixnetCommandServiceAdapter = new MixnetCommandServiceAdapter();

           mixnetCommandServiceAdapter.init(null);       // TODO Discuss unified configuration across system.
           //mixnetCommandServiceAdapter.open();

        } catch (Exception e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
    }


    @Override
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {

        if ("/api/nodes".equals(request.getRequestURI())) {
            response.setContentType("application/json");
            writeObject(mixnetCommandServiceAdapter.getNodeInfo(),response);
            baseRequest.setHandled(true);
            return;
        }

        if ("/api/commands".equals(request.getRequestURI()))
        {
            response.setContentType("application/json");
            writeObject(mixnetCommandServiceAdapter.getCommandList(), response);
            baseRequest.setHandled(true);
            return;
        }


        System.out.println(request.getRequestURI());
        response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        response.setContentType("text/plain");
        response.getOutputStream().write("Unknown call.".getBytes(Charset.defaultCharset()));
        baseRequest.setHandled(true);
    }


    private void writeObject(Object o, HttpServletResponse resp) throws IOException {
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setContentType("application/json");
        OutputStream os = resp.getOutputStream();
        objectMapper.writeValue(os,o);
        os.flush();
        os.close();
    }
}
