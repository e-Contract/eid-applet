/*
 * eID Applet Project.
 * Copyright (C) 2008-2009 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package test.be.fedict.eid.applet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Servlet to download an XML Signature from the HTTP session context.
 * 
 * @author Frank Cornelis
 * 
 */
public class XmlSignatureServlet extends HttpServlet {

	private static final Log LOG = LogFactory.getLog(XmlSignatureServlet.class);

	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		LOG.debug("doGet");
		HttpSession httpSession = request.getSession();
		String documentStr = (String) httpSession.getAttribute("xmlDocument");
		response.setContentType("text/xml");
		response.setHeader("Cache-Control",
				"no-cache, no-store, must-revalidate, max-age=-1"); // http 1.1
		response.setHeader("Pragma", "no-cache, no-store"); // http 1.0
		response.setDateHeader("Expires", -1);
		ServletOutputStream out = response.getOutputStream();
		out.write(documentStr.getBytes());
		out.close();
	}
}
