/*
 * eID Applet Project.
 * Copyright (C) 2009 Frank Cornelis.
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

package be.fedict.eid.applet.beta;

import javax.persistence.EntityManager;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class TestReportFactory {

	private static final Log LOG = LogFactory.getLog(TestReportFactory.class);

	private static final String TEST_REPORT_ID_SESSION_ATTRIBUTE = TestReportFactory.class
			.getName()
			+ ".testReportId";

	private final HttpSession httpSession;

	private final EntityManager entityManager;

	public TestReportFactory(EntityManager entityManager) {
		HttpServletRequest httpServletRequest = getHttpServletRequest();
		this.httpSession = httpServletRequest.getSession();
		this.entityManager = entityManager;
	}

	private HttpServletRequest getHttpServletRequest() {
		HttpServletRequest httpServletRequest;
		try {
			httpServletRequest = (HttpServletRequest) PolicyContext
					.getContext("javax.servlet.http.HttpServletRequest");
		} catch (PolicyContextException e) {
			throw new RuntimeException("JACC error: " + e.getMessage());
		}
		return httpServletRequest;
	}

	public void startTestReport(String javaVersion, String javaVendor,
			String osName, String osArch, String osVersion, String userAgent,
			String navigatorAppName, String navigatorAppVersion,
			String navigatorUserAgent) {
		TestReportEntity testReportEntity = new TestReportEntity(javaVersion,
				javaVendor, osName, osArch, osVersion, userAgent,
				navigatorAppName, navigatorAppVersion, navigatorUserAgent);
		this.entityManager.persist(testReportEntity);
		int testReportId = testReportEntity.getId();
		LOG.debug("test report Id: " + testReportId);
		this.httpSession.setAttribute(TEST_REPORT_ID_SESSION_ATTRIBUTE,
				testReportId);
	}

	public void finalizeTestReport(TestReportType test, TestReportResult result) {
		Integer testReportId = (Integer) this.httpSession
				.getAttribute(TEST_REPORT_ID_SESSION_ATTRIBUTE);
		if (null == testReportId) {
			throw new IllegalStateException("start the test report first");
		}
		TestReportEntity testReportEntity = this.entityManager.find(
				TestReportEntity.class, testReportId);
		if (null == testReportEntity) {
			throw new IllegalStateException("test report not found");
		}
		LOG.debug("updating test report " + testReportId + " " + test
				+ " result " + result);
		testReportEntity.setTest(test);
		testReportEntity.setResult(result);
		this.httpSession.removeAttribute(TEST_REPORT_ID_SESSION_ATTRIBUTE);
	}
}
