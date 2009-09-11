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

package be.fedict.eid.applet.beta.webapp;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.beta.OOXMLUploader;

public class OOXMLDownloadServlet extends HttpServlet {

	private static final Log LOG = LogFactory
			.getLog(OOXMLDownloadServlet.class);

	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		LOG.debug("doGet");
		HttpSession httpSession = request.getSession();
		URL ooxmlUrl = (URL) httpSession
				.getAttribute(OOXMLUploader.OOXML_URL_SESSION_ATTRIBUTE);
		response
				.setContentType("application/vnd.openxmlformats-officedocument.wordprocessingml.document");

		response.setHeader("Cache-Control",
				"no-cache, no-store, must-revalidate, max-age=-1"); // http 1.1
		if (false == request.getScheme().equals("https")) {
			// else the download fails in IE
			response.setHeader("Pragma", "no-cache"); // http 1.0
		} else {
			response.setHeader("Pragma", "public");
		}
		response.setDateHeader("Expires", -1);
		response.setHeader("Content-disposition", "attachment");
		try {
			File ooxmlFile = new File(ooxmlUrl.toURI());
			response.setContentLength((int) ooxmlFile.length());
		} catch (URISyntaxException e) {
			LOG.error("uri " + e.getMessage(), e);
		}

		ServletOutputStream out = response.getOutputStream();
		IOUtils.copy(ooxmlUrl.openStream(), out);
		out.close();
	}
}
