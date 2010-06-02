/*
 * eID Applet Project.
 * Copyright (C) 2009 FedICT.
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
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Servlet to retrieve the eID identity data from the HTTP session context via
 * JSON.
 * 
 * @author Frank Cornelis
 */
public class JSONServlet extends HttpServlet {

	private static final Log LOG = LogFactory.getLog(JSONServlet.class);

	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		LOG.debug("doGet");
		HttpSession httpSession = request.getSession();
		EIdData eIdData = (EIdData) httpSession.getAttribute("eid");
		// we could use the json-lib here
		PrintWriter writer = response.getWriter();
		writer.println("{");
		{
			writer.println("\tidentity: {");
			{
				Identity identity = eIdData.identity;
				writer.println("\t\tname: \"" + identity.name + "\",");
				writer
						.println("\t\tfirstName: \"" + identity.firstName
								+ "\",");
				writer.println("\t\tdateOfBirth: \""
						+ identity.dateOfBirth.getTime() + "\",");
				writer.println("\t\tgender: \"" + identity.gender + "\"");
			}
			writer.println("\t}");

			Address address = eIdData.address;
			if (null != address) {
				writer.println(",\taddress: {");
				{
					writer.println("\t\tstreetAndNumber: \""
							+ address.streetAndNumber + "\",");
					writer.println("\t\tmunicipality: \""
							+ address.municipality + "\",");
					writer.println("\t\tzip: \"" + address.zip + "\"");
				}
				writer.println("\t}");
			}
		}
		writer.println("}");
	}
}
