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
		logTestResult("Authentication", "Successful");
	}

	private void logTestResult(String test, String result) {
		SessionContextEntity sessionContext = this.sessionContextManager
				.getSessionContext();
		TestResultEntity testResultEntity = new TestResultEntity(test, result,
				sessionContext);
		this.entityManager.persist(testResultEntity);
	}

	public void authenticationError(String remoteAddress,
			X509Certificate clientCertificate) {
		logTestResult("Authentication", "Error");
	}

	public void identityIntegrityError(String remoteAddress) {
		logTestResult("Identification", "Error");
	}

	public void signatureError(String remoteAddress,
			X509Certificate clientCertificate) {
		logTestResult("Signature", "Error");
	}

	public void signed(String userId) {
		logTestResult("Signature", "Successful");
	}

	public void identified(String userId) {
		logTestResult("Identification", "Successful");
	}
}
