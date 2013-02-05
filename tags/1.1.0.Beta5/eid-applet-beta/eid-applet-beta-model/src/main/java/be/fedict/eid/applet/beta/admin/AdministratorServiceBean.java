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

package be.fedict.eid.applet.beta.admin;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.Local;
import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.security.auth.x500.X500Principal;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.security.Credentials;
import org.jboss.seam.util.Hex;

import be.fedict.eid.applet.service.spi.AuthenticationService;

/**
 * Authentication Services that manages administrator login.
 * 
 * @author Frank Cornelis
 * 
 */
@Stateless
@Local(AuthenticationService.class)
@LocalBinding(jndiBinding = "fedict/eid/applet/beta/AdministratorServiceBean")
public class AdministratorServiceBean implements AuthenticationService {

	private static final Log LOG = LogFactory
			.getLog(AdministratorServiceBean.class);

	@PersistenceContext
	private EntityManager entityManager;

	private void register(PublicKey publicKey, String serialNumber) {
		AdministratorEntity administratorEntity = new AdministratorEntity();
		administratorEntity.setPublicKey(publicKey.getEncoded());
		administratorEntity.setSerialNumber(serialNumber);
		this.entityManager.persist(administratorEntity);
	}

	private boolean isRegistered() {
		return false == this.entityManager.createQuery(
				"FROM AdministratorEntity").getResultList().isEmpty();
	}

	public void validateCertificateChain(List<X509Certificate> certificateChain)
			throws SecurityException {
		/*
		 * We're not using the entire PKI infrastructure here since we are in
		 * control of the admin token ourselves.
		 */
		X509Certificate adminCert = certificateChain.get(0);
		PublicKey adminPublicKey = adminCert.getPublicKey();
		String userId = getUserId(adminCert);
		if (isRegistered()) {
			LOG.debug("admin login");
		} else {
			LOG.debug("admin registration");
			register(adminPublicKey, userId);
		}

		String adminPassword = new String(Hex.encodeHex(adminPublicKey
				.getEncoded()));

		HttpServletRequest httpServletRequest;
		try {
			httpServletRequest = (HttpServletRequest) PolicyContext
					.getContext("javax.servlet.http.HttpServletRequest");
		} catch (PolicyContextException e) {
			throw new RuntimeException("JACC error: " + e.getMessage());
		}

		HttpSession httpSession = httpServletRequest.getSession();
		Credentials credentials = (Credentials) httpSession
				.getAttribute("org.jboss.seam.security.credentials");

		LOG.debug("username: " + userId);
		/*
		 * Pass the eID credentials to the JBoss Seam security framework.
		 */
		credentials.setUsername(userId);
		credentials.setPassword(adminPassword);
	}

	private String getUserId(X509Certificate adminCert) {
		X500Principal userPrincipal = adminCert.getSubjectX500Principal();
		String name = userPrincipal.toString();
		int serialNumberValueBeginIdx = name.indexOf("SERIALNUMBER=")
				+ "SERIALNUMBER=".length();
		int serialNumberValueEndIdx = name.indexOf(",",
				serialNumberValueBeginIdx);
		if (-1 == serialNumberValueEndIdx) {
			serialNumberValueEndIdx = name.length();
		}
		String userId = name.substring(serialNumberValueBeginIdx,
				serialNumberValueEndIdx);
		return userId;
	}
}