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

import be.fedict.eid.applet.service.impl.PdfGenerator;

import com.lowagie.text.DocumentException;

/**
 * Servlet that outputs the eID identity data from the HTTP session to a PDF.
 * Can be used by web applications in case they want to print-out the identity
 * information of a citizen.
 * 
 * @author fcorneli
 * 
 */
public class PdfServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory.getLog(PdfServlet.class);

	private PdfGenerator pdfGenerator;

	@Override
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		this.pdfGenerator = new PdfGenerator();
	}

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		LOG.debug("doGet");

		HttpSession httpSession = request.getSession();
		EIdData eIdData = (EIdData) httpSession.getAttribute("eid");

		byte[] document;
		try {
			document = this.pdfGenerator.generatePdf(eIdData);
		} catch (DocumentException e) {
			throw new ServletException(
					"PDF generator error: " + e.getMessage(), e);
		}

		response.setHeader("Expires", "0");
		response.setHeader("Cache-Control",
				"must-revalidate, post-check=0, pre-check=0");
		response.setHeader("Pragma", "public");

		response.setContentType("application/pdf");
		response.setContentLength(document.length);
		ServletOutputStream out = response.getOutputStream();
		out.write(document);
		out.flush();
	}
}
