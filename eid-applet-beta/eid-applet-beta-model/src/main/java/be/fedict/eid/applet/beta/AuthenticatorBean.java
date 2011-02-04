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

import java.util.Arrays;
import java.util.List;

import javax.ejb.Stateless;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Observer;
import org.jboss.seam.security.Credentials;
import org.jboss.seam.security.Identity;
import org.jboss.seam.util.Hex;

import be.fedict.eid.applet.beta.admin.AdministratorEntity;

@Stateless
@Name("authenticator")
@LocalBinding(jndiBinding = "fedict/eid/applet/beta/AuthenticatorBean")
public class AuthenticatorBean implements Authenticator {

	private static final Log LOG = LogFactory.getLog(AuthenticatorBean.class);

	@PersistenceContext
	private EntityManager entityManager;

	@In
	private Credentials credentials;

	@In
	private Identity identity;

	@In
	private FacesContext facesContext;

	@SuppressWarnings("unchecked")
	public boolean authenticate() {
		LOG.debug("authenticate");

		String password = this.credentials.getPassword();
		byte[] encodedPublicKey = Hex.decodeHex(password.toCharArray());

		List<AdministratorEntity> adminEntities = this.entityManager
				.createQuery("FROM AdministratorEntity").getResultList();

		for (AdministratorEntity administratorEntity : adminEntities) {
			if (Arrays.equals(administratorEntity.getPublicKey(),
					encodedPublicKey)) {
				this.identity.addRole("admin");
				return true;
			}
		}
		return true;
	}

	@Observer(Identity.EVENT_LOGIN_FAILED)
	public void loginFailedCallback() {
		/*
		 * XXX: doesn't seam to work.
		 */
		LOG.debug("login failed callback");
		this.facesContext.addMessage(null, new FacesMessage(
				FacesMessage.SEVERITY_WARN, "Login failed. Try again.",
				"Incorrect authentication certificate."));
	}
}
