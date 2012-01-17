package be.fedict.eid.applet.service.cdi;

import java.security.cert.X509Certificate;

import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.servlet.http.HttpSession;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.cdi.BelgianCertificate.CERTIFICATE_TYPE;
import be.fedict.eid.applet.service.impl.handler.IdentityDataMessageHandler;

/**
 * CDI producer of eID Applet Service data.
 * 
 * @author Frank Cornelis
 * 
 */
public class BelgianIdentityCardProducer {

	@Inject
	private HttpSession httpSession;

	@Produces
	public Identity createIdentity() {
		Identity identity = (Identity) this.httpSession
				.getAttribute(IdentityDataMessageHandler.IDENTITY_SESSION_ATTRIBUTE);
		return identity;
	}

	@Produces
	public Address createAddress() {
		Address address = (Address) this.httpSession
				.getAttribute(IdentityDataMessageHandler.ADDRESS_SESSION_ATTRIBUTE);
		return address;
	}

	@Produces
	@BelgianCertificate(CERTIFICATE_TYPE.AUTH)
	public X509Certificate createAuthCert() {
		X509Certificate cert = (X509Certificate) this.httpSession
				.getAttribute(IdentityDataMessageHandler.AUTHN_CERT_SESSION_ATTRIBUTE);
		return cert;
	}

	@Produces
	@BelgianCertificate(CERTIFICATE_TYPE.SIGN)
	public X509Certificate createSignCert() {
		X509Certificate cert = (X509Certificate) this.httpSession
				.getAttribute(IdentityDataMessageHandler.SIGN_CERT_SESSION_ATTRIBUTE);
		return cert;
	}

	@Produces
	@BelgianCertificate(CERTIFICATE_TYPE.CITIZEN_CA)
	public X509Certificate createCitizenCACert() {
		X509Certificate cert = (X509Certificate) this.httpSession
				.getAttribute(IdentityDataMessageHandler.CA_CERT_SESSION_ATTRIBUTE);
		return cert;
	}

	@Produces
	@BelgianCertificate(CERTIFICATE_TYPE.ROOT_CA)
	public X509Certificate createRootCACert() {
		X509Certificate cert = (X509Certificate) this.httpSession
				.getAttribute(IdentityDataMessageHandler.ROOT_CERT_SESSION_ATTRIBUTE);
		return cert;
	}
}
