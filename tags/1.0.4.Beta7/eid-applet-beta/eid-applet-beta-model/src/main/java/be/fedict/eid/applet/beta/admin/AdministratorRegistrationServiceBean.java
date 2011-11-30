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

import javax.annotation.security.RolesAllowed;
import javax.ejb.Local;
import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.security.auth.x500.X500Principal;

import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.ejb3.annotation.SecurityDomain;

import be.fedict.eid.applet.service.spi.AuthenticationService;

@Stateless
@Local(AuthenticationService.class)
@LocalBinding(jndiBinding = "fedict/eid/applet/beta/AdministratorRegistrationServiceBean")
@SecurityDomain("eid-applet-beta")
public class AdministratorRegistrationServiceBean implements
		AuthenticationService {

	@PersistenceContext
	private EntityManager entityManager;

	private void register(PublicKey publicKey, String serialNumber) {
		AdministratorEntity administratorEntity = new AdministratorEntity();
		administratorEntity.setPublicKey(publicKey.getEncoded());
		administratorEntity.setSerialNumber(serialNumber);
		this.entityManager.persist(administratorEntity);
	}

	@RolesAllowed("admin")
	public void validateCertificateChain(List<X509Certificate> certificateChain)
			throws SecurityException {
		/*
		 * We're not using the entire PKI infrastructure here since we are in
		 * control of the admin token ourselves.
		 */
		X509Certificate adminCert = certificateChain.get(0);
		PublicKey adminPublicKey = adminCert.getPublicKey();
		String userId = getUserId(adminCert);
		register(adminPublicKey, userId);
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