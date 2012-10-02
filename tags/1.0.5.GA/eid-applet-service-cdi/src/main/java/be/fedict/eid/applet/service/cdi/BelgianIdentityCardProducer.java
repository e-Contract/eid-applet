package be.fedict.eid.applet.service.cdi;

import java.security.cert.X509Certificate;
import java.util.Map;

import javax.enterprise.inject.Produces;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.cdi.BelgianCertificate.CERTIFICATE_TYPE;
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

	private <T> T getSessionAttribute(Class<? extends T> clazz,
			String attributeName) {
		FacesContext facesContext = FacesContext.getCurrentInstance();
		ExternalContext externalContext = facesContext.getExternalContext();
		Map<String, Object> sessionMap = externalContext.getSessionMap();
		T sessionAttribute = (T) sessionMap.get(attributeName);
		return sessionAttribute;
	}
}
