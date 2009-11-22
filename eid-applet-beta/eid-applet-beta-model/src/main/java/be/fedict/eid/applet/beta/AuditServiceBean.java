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

package be.fedict.eid.applet.beta;

import java.security.cert.X509Certificate;

import javax.ejb.EJB;
import javax.ejb.Local;
import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.jboss.ejb3.annotation.LocalBinding;

import be.fedict.eid.applet.service.spi.AuditService;

@Stateless
@Local(AuditService.class)
@LocalBinding(jndiBinding = "fedict/eid/applet/beta/AuditServiceBean")
public class AuditServiceBean implements AuditService {

	@EJB
	private SessionContextManager sessionContextManager;

	@PersistenceContext
	private EntityManager entityManager;

	public void authenticated(String userId) {
		logTestResult(TestReportType.AUTHENTICATION,
				TestReportResult.SUCCESSFUL);
	}

	private void logTestResult(TestReportType test, TestReportResult result) {
		SessionContextEntity sessionContext = this.sessionContextManager
				.getSessionContext();
		TestResultEntity testResultEntity = new TestResultEntity(test.name(),
				result.name(), sessionContext);
		this.entityManager.persist(testResultEntity);

		TestReportFactory testReportFactory = new TestReportFactory(
				this.entityManager);
		testReportFactory.finalizeTestReport(test, result);

	}

	public void authenticationError(String remoteAddress,
			X509Certificate clientCertificate) {
		logTestResult(TestReportType.AUTHENTICATION, TestReportResult.FAILED);
	}

	public void identityIntegrityError(String remoteAddress) {
		logTestResult(TestReportType.IDENTIFICATION, TestReportResult.FAILED);
	}

	public void signatureError(String remoteAddress,
			X509Certificate clientCertificate) {
		logTestResult(TestReportType.SIGNATURE, TestReportResult.FAILED);
	}

	public void signed(String userId) {
		logTestResult(TestReportType.SIGNATURE, TestReportResult.SUCCESSFUL);
	}

	public void identified(String userId) {
		logTestResult(TestReportType.IDENTIFICATION,
				TestReportResult.SUCCESSFUL);
	}
}
