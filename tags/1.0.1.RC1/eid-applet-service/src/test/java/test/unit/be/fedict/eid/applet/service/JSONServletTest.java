/*
 * eID Applet Project.
 * Copyright (C) 2008-2010 FedICT.
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

import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.GregorianCalendar;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.json.simple.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mortbay.jetty.testing.ServletTester;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.EIdCertsData;
import be.fedict.eid.applet.service.EIdData;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.JSONServlet;

public class JSONServletTest {

	private static final Log LOG = LogFactory.getLog(JSONServletTest.class);

	private ServletTester servletTester;

	private String location;

	@Before
	public void setUp() throws Exception {
		this.servletTester = new ServletTester();
		this.servletTester.addServlet(JSONServlet.class, "/");

		this.servletTester.start();
		this.location = this.servletTester.createSocketConnector(true);
	}

	@After
	public void tearDown() throws Exception {
		this.servletTester.stop();
	}

	@Test
	public void testGetWithoutSessionData() throws Exception {
		// setup
		LOG.debug("location: " + this.location);
		HttpClient httpClient = new HttpClient();
		GetMethod getMethod = new GetMethod(this.location);

		// operate
		int statusCode = httpClient.executeMethod(getMethod);

		// verify
		assertEquals(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, statusCode);
		LOG.debug("result content: " + getMethod.getResponseBodyAsString());
	}

	@Test
	public void testJSONOutput() throws Exception {
		// setup
		EIdData eIdData = new EIdData();
		eIdData.identity = new Identity();
		eIdData.identity.nationalNumber = "123456789";
		eIdData.identity.dateOfBirth = new GregorianCalendar();
		eIdData.identity.cardValidityDateBegin = new GregorianCalendar();
		eIdData.identity.cardValidityDateEnd = new GregorianCalendar();
		eIdData.address = new Address();
		eIdData.address.streetAndNumber = "test-street-1234";

		eIdData.certs = new EIdCertsData();
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(5);
		X509Certificate certificate = MiscTestUtils.generateCertificate(keyPair
				.getPublic(), "CN=Test", notBefore, notAfter, null, keyPair
				.getPrivate(), false, 0, null, null);
		eIdData.certs.authn = certificate;

		StringWriter stringWriter = new StringWriter();
		PrintWriter printWriter = new PrintWriter(stringWriter);

		// operate
		JSONServlet.outputJSON(eIdData, printWriter);

		// verify
		String jsonOutput = stringWriter.toString();
		LOG.debug("JSON output: " + jsonOutput);
	}

	@Test
	public void testJSONSimpleSpike() throws Exception {
		JSONObject eidJSONObject = new JSONObject();
		JSONObject identityJSONObject = new JSONObject();
		eidJSONObject.put("identity", identityJSONObject);
		identityJSONObject.put("nationalNumber", "12345678");
		identityJSONObject
				.put("dateOfBirth", new GregorianCalendar().getTime());

		LOG.debug("JSON result: " + eidJSONObject.toJSONString());
	}
}
