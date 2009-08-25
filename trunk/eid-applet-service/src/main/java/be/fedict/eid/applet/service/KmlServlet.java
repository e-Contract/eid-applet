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

package be.fedict.eid.applet.service;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.impl.KmlGenerator;
import be.fedict.eid.applet.service.util.KmlLight;

/**
 * Servlet that outputs the eID identity data from the HTTP session to a 
 * zipped KML (.kmz)
 * Can be used by virtual globes like Google Earth, KDE Marble...
 * @see http://www.opengeospatial.org/standards/kml/
 *
 * @author Bart Hanssens
 * 
 */
public class KmlServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory.getLog(KmlServlet.class);

	private KmlGenerator kmlGenerator;

	@Override
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		this.kmlGenerator = new KmlGenerator();
	}

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		LOG.debug("doGet");

		HttpSession httpSession = request.getSession();
		EIdData eIdData = (EIdData) httpSession.getAttribute("eid");

		byte[] document;
		try {
                    document = this.kmlGenerator.generateKml(eIdData);
		} catch (IOException e) {
			throw new ServletException(
				"KML generator error: " + e.getMessage(), e);
		}

		response.setHeader("Expires", "0");
		response.setHeader("Cache-Control",
				"must-revalidate, post-check=0, pre-check=0");
		response.setHeader("Pragma", "public");

		response.setContentType(KmlLight.MIME_TYPE);
		response.setContentLength(document.length);
		ServletOutputStream out = response.getOutputStream();
		out.write(document);
		out.flush();
	}
}
