/*
 * eID Applet Project.
 * Copyright (C) 2008-2012 FedICT.
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

package be.fedict.eid.applet.service.cdi;

import java.security.cert.X509Certificate;
import java.util.Map;

import javax.enterprise.inject.Produces;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.cdi.BelgianCertificate.CERTIFICATE_TYPE;
import be.fedict.eid.applet.service.impl.handler.AuthenticationDataMessageHandler;
import be.fedict.eid.applet.service.impl.handler.IdentityDataMessageHandler;

/**
 * CDI/JSF producer of eID Applet Service data.
 * 
 * @author Frank Cornelis
 * 
 */
public class BelgianIdentityCardProducer {

	@Produces
	public Identity createIdentity() {
		Identity identity = getSessionAttribute(Identity.class,
				IdentityDataMessageHandler.IDENTITY_SESSION_ATTRIBUTE);
		return identity;
	}

	@Produces
	public Address createAddress() {
		Address address = getSessionAttribute(Address.class,
				IdentityDataMessageHandler.ADDRESS_SESSION_ATTRIBUTE);
		return address;
	}

	@Produces
	@BelgianCertificate(CERTIFICATE_TYPE.AUTH)
	public X509Certificate createAuthCert() {
		X509Certificate cert = getSessionAttribute(X509Certificate.class,
				IdentityDataMessageHandler.AUTHN_CERT_SESSION_ATTRIBUTE);
		return cert;
	}

	@Produces
	@BelgianCertificate(CERTIFICATE_TYPE.SIGN)
	public X509Certificate createSignCert() {
		X509Certificate cert = getSessionAttribute(X509Certificate.class,
				IdentityDataMessageHandler.SIGN_CERT_SESSION_ATTRIBUTE);
		return cert;
	}

	@Produces
	@BelgianCertificate(CERTIFICATE_TYPE.CITIZEN_CA)
	public X509Certificate createCitizenCACert() {
		X509Certificate cert = getSessionAttribute(X509Certificate.class,
				IdentityDataMessageHandler.CA_CERT_SESSION_ATTRIBUTE);
		return cert;
	}

	@Produces
	@BelgianCertificate(CERTIFICATE_TYPE.ROOT_CA)
	public X509Certificate createRootCACert() {
		X509Certificate cert = getSessionAttribute(X509Certificate.class,
				IdentityDataMessageHandler.ROOT_CERT_SESSION_ATTRIBUTE);
		return cert;
	}

	@Produces
	@BelgianCitizen
	public String createAuthenticatedBelgianCitizenIdentifier() {
		String userId = (String) getSessionAttribute(
				String.class,
				AuthenticationDataMessageHandler.AUTHENTICATED_USER_IDENTIFIER_SESSION_ATTRIBUTE);
		return userId;
	}

	private <T> T getSessionAttribute(Class<? extends T> clazz,
			String attributeName) {
		FacesContext facesContext = FacesContext.getCurrentInstance();
		ExternalContext externalContext = facesContext.getExternalContext();
		Map<String, Object> sessionMap = externalContext.getSessionMap();
		T sessionAttribute = (T) sessionMap.get(attributeName);
		return sessionAttribute;
	}
}
