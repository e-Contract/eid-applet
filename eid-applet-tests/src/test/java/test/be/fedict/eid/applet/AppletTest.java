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

import static org.junit.Assert.assertTrue;

import java.net.ServerSocket;

import javax.swing.JOptionPane;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.server.RemoteControlConfiguration;
import org.openqa.selenium.server.SeleniumServer;

import com.thoughtworks.selenium.DefaultSelenium;
import com.thoughtworks.selenium.Selenium;
import com.thoughtworks.selenium.SeleniumLogLevels;

/**
 * Integration tests for Applet.
 * 
 * @author Frank Cornelis
 * 
 */
public class AppletTest {

	private static final Log LOG = LogFactory.getLog(AppletTest.class);

	private SeleniumServer seleniumServer;

	private String location;

	private Selenium selenium;

	public static int getFreePort() throws Exception {
		ServerSocket serverSocket = new ServerSocket(0);
		int port = serverSocket.getLocalPort();
		serverSocket.close();
		return port;
	}

	private void start() throws Exception {
		RemoteControlConfiguration config = new RemoteControlConfiguration();
		int seleniumPort = getFreePort();
		LOG.debug("configured selenium port: " + seleniumPort);
		config.setPort(seleniumPort);
		this.seleniumServer = new SeleniumServer(config);
		this.seleniumServer.start();
		// int seleniumPort = this.seleniumServer.getPort();
		LOG.debug("selenium port: " + this.seleniumServer.getPort());
		String browserStartCommand = "*firefox";
		this.selenium = new DefaultSelenium("localhost", seleniumPort,
				browserStartCommand, "http://www.google.be");
		LOG.debug("starting selenium...");
		this.selenium.start();
		LOG.debug("selenium started.");
		this.selenium.setBrowserLogLevel(SeleniumLogLevels.INFO);
	}

	protected void stop() throws Exception {
		if (null != this.selenium) {
			this.selenium.stop();
			this.selenium = null;
		}
		if (null != this.seleniumServer) {
			this.seleniumServer.stop();
			this.seleniumServer = null;
		}
	}

	@Before
	public void setUp() throws Exception {
		start();
	}

	@After
	public void tearDown() throws Exception {
		stop();
	}

	@Test
	public void testWelcomePage() throws Exception {
		LOG.debug("test welcome page");
		this.selenium.open("chrome://pippki/content/certManager.xul");

		JOptionPane.showMessageDialog(null,
				"Waiting for certificate configuration...");

		this.selenium.open("https://localhost/eid-applet-test/");
		assertTrue(this.selenium
				.isTextPresent("eID Applet Test Web Application"));
	}

	@Test
	public void testIdentification() throws Exception {
		LOG.debug("functional eID identification test");

		this.selenium.open("chrome://pippki/content/certManager.xul");

		JOptionPane.showMessageDialog(null,
				"Waiting for certificate configuration...");

		JOptionPane.showMessageDialog(null,
				"Remove your eID from your card reader...");
		this.selenium.open("https://localhost/eid-applet-test/identify.jsp");
		assertTrue(this.selenium
				.isTextPresent("eID Applet Identification Demo"));

		JOptionPane.showMessageDialog(null,
				"Press OK after the eID operation completed...");

		assertTrue(this.selenium.isTextPresent("Identity Result Page"));

		JOptionPane.showMessageDialog(null, "End of functional test.");
	}

	@Test
	public void testAuthentication() throws Exception {
		LOG.debug("functional eID authentication test");

		this.selenium.open("chrome://pippki/content/certManager.xul");

		JOptionPane.showMessageDialog(null,
				"Waiting for certificate configuration...");

		this.selenium
				.open("https://localhost/eid-applet-test/authenticate.jsp");
		assertTrue(this.selenium
				.isTextPresent("eID Applet Authentication Demo"));

		while (false == this.selenium
				.isTextPresent("Authentication Result Page")) {
			LOG.debug("waiting for eID Applet completion...");
			Thread.sleep(1000);
		}
		assertTrue(this.selenium
				.isTextPresent("Authenticated User Identifier:"));
		assertTrue(this.selenium
				.isTextPresent("Signature Algorithm: SHA1withRSA, OID = 1.2.840.113549.1.1.5"));
	}

	@Test
	public void testSignature() throws Exception {
		LOG.debug("functional eID signature test");

		this.selenium.open("chrome://pippki/content/certManager.xul");

		JOptionPane.showMessageDialog(null,
				"Waiting for certificate configuration...");

		this.selenium.open("https://localhost/eid-applet-test/sign-text.jsp");
		assertTrue(this.selenium.isTextPresent("eID Applet Signature Demo"));

		this.selenium.type("toBeSigned", "Hello World");
		this.selenium.click("//input");

		assertTrue(this.selenium.isTextPresent("eID Applet Signature Test"));
		while (false == this.selenium
				.isTextPresent("eID Applet Signature Demo")) {
			LOG.debug("waiting for eID Applet completion...");
			Thread.sleep(1000);
		}
		assertTrue(this.selenium
				.isTextPresent("Signature created successfully."));
		assertTrue(this.selenium
				.isTextPresent("Signature Algorithm: SHA1withRSA, OID = 1.2.840.113549.1.1.5"));
	}
}
