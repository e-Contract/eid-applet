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

import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import javax.ejb.Remove;
import javax.ejb.Stateful;

import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.annotations.Destroy;
import org.jboss.seam.annotations.Factory;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Out;
import org.jboss.seam.log.Log;

import be.fedict.eid.applet.service.signer.ODFSignatureVerifier;

@Stateful
@Name("odfViewer")
@LocalBinding(jndiBinding = "fedict/eid/applet/beta/ODFViewerBean")
public class ODFViewerBean implements ODFViewer {

	@Logger
	private Log log;

	@SuppressWarnings("unused")
	@Out
	private List<X509Certificate> signers;

	@In(ODFTempFileManager.ODF_URL_SESSION_ATTRIBUTE)
	private URL odfFileUrl;

	@Remove
	@Destroy
	public void destroy() {
		this.log.debug("destroy");
	}

	@Factory("signers")
	public void createSignersList() {
		this.log.debug("create signers list");
		try {
			this.signers = ODFSignatureVerifier.getSigners(this.odfFileUrl);
		} catch (Exception e) {
			this.log.error("ODF signature verification error: "
					+ e.getMessage());
			this.signers = new LinkedList<X509Certificate>();
		}
	}
}
