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

package be.fedict.eid.applet.beta;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.Local;
import javax.ejb.Stateless;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.ejb3.annotation.LocalBinding;

import be.fedict.eid.applet.service.spi.IdentityIntegrityService;

@Stateless
@Local(IdentityIntegrityService.class)
@LocalBinding(jndiBinding = "fedict/eid/applet/beta/IdentityIntegrityServiceBean")
public class IdentityIntegrityServiceBean implements IdentityIntegrityService {

	private static final Log LOG = LogFactory
			.getLog(IdentityIntegrityServiceBean.class);

	public void checkNationalRegistrationCertificate(
			List<X509Certificate> certificateChain) throws SecurityException {
		LOG.debug("checking national registry certificate...");

		HttpServletRequest httpServletRequest;
		try {
			httpServletRequest = (HttpServletRequest) PolicyContext
					.getContext("javax.servlet.http.HttpServletRequest");
		} catch (PolicyContextException e) {
			throw new RuntimeException("JACC error: " + e.getMessage());
		}

		HttpSession httpSession = httpServletRequest.getSession();
		X509Certificate certificate = certificateChain.get(0);
		httpSession.setAttribute("nationalRegistryCertificate", certificate);
	}
}
