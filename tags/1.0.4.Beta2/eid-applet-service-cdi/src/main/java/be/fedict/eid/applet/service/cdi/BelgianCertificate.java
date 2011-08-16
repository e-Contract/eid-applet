package be.fedict.eid.applet.service.cdi;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import javax.inject.Qualifier;

/**
 * CDI qualifier for injecting X509 certificates.
 * 
 * @author Frank Cornelis
 * 
 */
@Qualifier
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.FIELD, ElementType.METHOD })
public @interface BelgianCertificate {

	CERTIFICATE_TYPE value();

	/**
	 * Enumeration of all available certificate types.
	 * 
	 * @author Frank Cornelis
	 * 
	 */
	public static enum CERTIFICATE_TYPE {
		AUTH, SIGN, CITIZEN_CA, ROOT_CA
	}
}
