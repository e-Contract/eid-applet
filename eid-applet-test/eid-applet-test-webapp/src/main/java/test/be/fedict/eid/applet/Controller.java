/*
 * eID Applet Project.
 * Copyright (C) 2014-2015 e-Contract.be BVBA.
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

import java.io.IOException;
import java.io.Serializable;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

import javax.enterprise.context.SessionScoped;
import javax.enterprise.event.Observes;
import javax.faces.application.FacesMessage;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.inject.Named;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.cdi.AuthenticatedEvent;
import be.fedict.eid.applet.service.cdi.AuthenticationEvent;
import be.fedict.eid.applet.service.cdi.BeIDContext;
import be.fedict.eid.applet.service.cdi.IdentificationEvent;
import be.fedict.eid.applet.service.cdi.IdentityEvent;
import be.fedict.eid.applet.service.cdi.SecureChannelBindingEvent;
import be.fedict.eid.applet.service.cdi.SignatureDigestEvent;
import be.fedict.eid.applet.service.cdi.SignatureEvent;
import be.fedict.eid.applet.service.cdi.StartEvent;
import be.fedict.eid.applet.service.cdi.StartEvent.AuthenticationRequest;
import be.fedict.eid.applet.service.cdi.StartEvent.IdentificationRequest;
import be.fedict.eid.applet.service.cdi.StartEvent.SigningRequest;
import be.fedict.eid.applet.service.spi.AuthorizationException;
import be.fedict.eid.applet.service.spi.CertificateSecurityException;
import be.fedict.eid.applet.service.spi.ExpiredCertificateSecurityException;
import be.fedict.eid.applet.service.spi.RevokedCertificateSecurityException;
import be.fedict.eid.applet.service.spi.TrustCertificateSecurityException;

@Named("cdiTest")
@SessionScoped
public class Controller implements Serializable {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory.getLog(Controller.class);

	public static enum Operation {
		IDENTIFICATION, AUTHENTICATION, SIGNING
	}

	public static enum PKIValidation {
		OK, CERTIFICATE_ERROR, CERTIFICATE_EXPIRED, CERTIFICATE_REVOKED, CERTIFICATE_NOT_TRUSTED, AUTHORIZATION
	}

	private Operation operation;

	private PKIValidation pkiValidation;

	private Identity identity;

	private String userIdentifier;

	private Address address;

	private boolean includeIdentity;

	private boolean includeAddress;

	private boolean includePhoto;

	private boolean includeCertificates;

	private boolean logoff;

	private boolean removeCard;

	private boolean secureChannelBinding;

	private X509Certificate serverCertificate;

	private String message;

	public String getMessage() {
		return this.message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public void loadAction() {
		if (null != this.message) {
			FacesContext facesContext = FacesContext.getCurrentInstance();
			facesContext.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_WARN, this.message, null));
			this.message = null;
		}
	}

	public void setOperation(Operation operation) {
		this.operation = operation;
	}

	public Operation getOperation() {
		return this.operation;
	}

	public Operation[] getOperations() {
		return Operation.values();
	}

	public PKIValidation getPkiValidation() {
		return this.pkiValidation;
	}

	public void setPkiValidation(PKIValidation pkiValidation) {
		this.pkiValidation = pkiValidation;
	}

	public PKIValidation[] getPkiValidations() {
		return PKIValidation.values();
	}

	public Identity getIdentity() {
		return this.identity;
	}

	public String getUserIdentifier() {
		return this.userIdentifier;
	}

	public Address getAddress() {
		return this.address;
	}

	public boolean isIncludeIdentity() {
		return this.includeIdentity;
	}

	public void setIncludeIdentity(boolean includeIdentity) {
		this.includeIdentity = includeIdentity;
	}

	public boolean isIncludeAddress() {
		return this.includeAddress;
	}

	public void setIncludeAddress(boolean includeAddress) {
		this.includeAddress = includeAddress;
	}

	public boolean isIncludePhoto() {
		return this.includePhoto;
	}

	public void setIncludePhoto(boolean includePhoto) {
		this.includePhoto = includePhoto;
	}

	public boolean isIncludeCertificates() {
		return this.includeCertificates;
	}

	public void setIncludeCertificates(boolean includeCertificates) {
		this.includeCertificates = includeCertificates;
	}

	public boolean isLogoff() {
		return this.logoff;
	}

	public void setLogoff(boolean logoff) {
		this.logoff = logoff;
	}

	public boolean isRemoveCard() {
		return this.removeCard;
	}

	public void setRemoveCard(boolean removeCard) {
		this.removeCard = removeCard;
	}

	public boolean isSecureChannelBinding() {
		return this.secureChannelBinding;
	}

	public void setSecureChannelBinding(boolean secureChannelBinding) {
		this.secureChannelBinding = secureChannelBinding;
	}

	public X509Certificate getServerCertificate() {
		return this.serverCertificate;
	}

	public void reset() {
		this.identity = null;
		this.address = null;
		this.userIdentifier = null;
		this.serverCertificate = null;
	}

	public void perform() throws IOException {
		FacesContext facesContext = FacesContext.getCurrentInstance();
		ExternalContext externalContext = facesContext.getExternalContext();
		externalContext.redirect(externalContext.getRequestContextPath() + "/cdi.html");
	}

	public void handleStart(@Observes @BeIDContext(IdentifyCDIServlet.CONTEXT) StartEvent startEvent) {
		LOG.debug("start event");
		switch (this.operation) {
		case IDENTIFICATION: {
			IdentificationRequest identificationRequest = startEvent.performIdentification();
			if (this.includeAddress) {
				identificationRequest.includeAddress();
			}
			if (this.includePhoto) {
				identificationRequest.includePhoto();
			}
			if (this.removeCard) {
				identificationRequest.removeCard();
			}
			if (this.includeCertificates) {
				identificationRequest.includeCertificates();
			}
			break;
		}
		case AUTHENTICATION: {
			AuthenticationRequest authenticationRequest = startEvent.performAuthentication();
			if (this.includeIdentity) {
				authenticationRequest.includeIdentity();
			}
			if (this.includeAddress) {
				authenticationRequest.includeAddress();
			}
			if (this.includePhoto) {
				authenticationRequest.includePhoto();
			}
			if (this.removeCard) {
				authenticationRequest.removeCard();
			}
			if (this.logoff) {
				authenticationRequest.logoff();
			}
			if (this.secureChannelBinding) {
				authenticationRequest.enableSecureChannelBinding();
			}
			break;
		}
		case SIGNING: {
			SigningRequest signingRequest = startEvent.performSigning();
			if (this.includeIdentity) {
				signingRequest.includeIdentity();
			}
			if (this.includeAddress) {
				signingRequest.includeAddress();
			}
			if (this.includePhoto) {
				signingRequest.includePhoto();
			}
			if (this.includeCertificates) {
				signingRequest.includeCertificates();
			}
			break;
		}
		default:
			throw new IllegalStateException("unsupported operation: " + this.operation);
		}
	}

	public void handleReset(@Observes @BeIDContext(IdentifyCDIServlet.CONTEXT) StartEvent startEvent) {
		reset();
	}

	public void handleIdentification(
			@Observes @BeIDContext(IdentifyCDIServlet.CONTEXT) IdentificationEvent identificationEvent)
					throws Exception {
		emulatePkiValidation();
		identificationEvent.valid();
	}

	public void handleIdentity(@Observes @BeIDContext(IdentifyCDIServlet.CONTEXT) IdentityEvent identityEvent) {
		LOG.debug("handle identity");
		LOG.debug("hello: " + identityEvent.getIdentity().getFirstName());
		this.identity = identityEvent.getIdentity();
		this.address = identityEvent.getAddress();
	}

	public void handleAuthCertValidation(
			@Observes @BeIDContext(IdentifyCDIServlet.CONTEXT) AuthenticationEvent authenticationEvent)
					throws Exception {
		emulatePkiValidation();
		authenticationEvent.valid();
	}

	public void handleAuthenticatedUser(
			@Observes @BeIDContext(IdentifyCDIServlet.CONTEXT) AuthenticatedEvent authenticatedEvent) {
		this.userIdentifier = authenticatedEvent.getUserIdentifier();
	}

	public void handleSignatureDigest(
			@Observes @BeIDContext(IdentifyCDIServlet.CONTEXT) SignatureDigestEvent signatureDigestEvent)
					throws Exception {
		if (this.includeCertificates && null == signatureDigestEvent.getSigningCertificateChain()) {
			throw new RuntimeException("signing certificates not included");
		}
		if (this.includeCertificates) {
			if (this.pkiValidation != null && this.pkiValidation == PKIValidation.AUTHORIZATION) {
				throw new AuthorizationException();
			}
		}
		byte[] data = "hello world".getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		messageDigest.update(data);
		byte[] digestValue = messageDigest.digest();
		String digestAlgo = "SHA1";
		signatureDigestEvent.sign(digestValue, digestAlgo, "test");
		if (this.removeCard) {
			signatureDigestEvent.removeCard();
		}
		if (this.logoff) {
			signatureDigestEvent.logoff();
		}
	}

	public void handleSignature(@Observes @BeIDContext(IdentifyCDIServlet.CONTEXT) SignatureEvent signatureEvent)
			throws Exception {
		LOG.debug("signature event");
		emulatePkiValidation();
	}

	private void emulatePkiValidation() throws Exception {
		if (null == this.pkiValidation) {
			return;
		}
		switch (this.pkiValidation) {
		case OK:
		case AUTHORIZATION:
			break;
		case CERTIFICATE_ERROR:
			throw new CertificateSecurityException();
		case CERTIFICATE_EXPIRED:
			throw new ExpiredCertificateSecurityException();
		case CERTIFICATE_REVOKED:
			throw new RevokedCertificateSecurityException();
		case CERTIFICATE_NOT_TRUSTED:
			throw new TrustCertificateSecurityException();
		}
	}

	public void handleSecureChannelBinding(
			@Observes @BeIDContext(IdentifyCDIServlet.CONTEXT) SecureChannelBindingEvent secureChannelBindingEvent) {
		LOG.debug("secure channel identity: "
				+ secureChannelBindingEvent.getServerCertificate().getSubjectX500Principal());
		this.serverCertificate = secureChannelBindingEvent.getServerCertificate();
		secureChannelBindingEvent.valid();
	}
}
