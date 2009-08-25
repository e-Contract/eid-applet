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

package test.unit.be.fedict.eid.applet.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mortbay.jetty.testing.ServletTester;

import be.fedict.eid.applet.service.KmlServlet;

public class KmlServletTest {

	private static final Log LOG = LogFactory.getLog(KmlServletTest.class);

	private ServletTester servletTester;

	private String location;

	@Before
	public void setUp() throws Exception {
		this.servletTester = new ServletTester();
		this.servletTester.addServlet(KmlServlet.class, "/");

		this.servletTester.start();
		this.location = this.servletTester.createSocketConnector(true);
	}

	@After
	public void tearDown() throws Exception {
		this.servletTester.stop();
	}

	@Test
	public void anonymousResult() throws Exception {
		// setup
		LOG.debug("location: " + this.location);
		HttpClient httpClient = new HttpClient();
		GetMethod getMethod = new GetMethod(this.location);

		// operate
		int statusCode = httpClient.executeMethod(getMethod);

		// verify
		assertEquals(HttpServletResponse.SC_OK, statusCode);
		String resultContentType = getMethod.getResponseHeader("content-type")
				.getValue();
		assertEquals("application/vnd.google-earth.kmz", resultContentType);
		assertTrue(getMethod.getResponseBody().length > 0);
	}
}
