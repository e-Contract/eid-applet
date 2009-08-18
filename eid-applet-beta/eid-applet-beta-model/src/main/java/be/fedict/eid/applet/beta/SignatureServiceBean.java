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

import java.io.OutputStream;
import java.net.URL;

import javax.ejb.EJB;
import javax.ejb.Local;
import javax.ejb.Stateless;

import org.apache.commons.io.output.ByteArrayOutputStream;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.ejb3.annotation.LocalBinding;

import be.fedict.eid.applet.service.signer.AbstractODFSignatureService;
import be.fedict.eid.applet.service.signer.HttpSessionTemporaryDataStorage;
import be.fedict.eid.applet.service.signer.TemporaryDataStorage;
import be.fedict.eid.applet.service.spi.SignatureService;

/**
 * Signature Service that manages the eID ODF signature test.
 * 
 * @author fcorneli
 * 
 */
@Stateless
@Local(SignatureService.class)
@LocalBinding(jndiBinding = "fedict/eid/applet/beta/SignatureServiceBean")
public class SignatureServiceBean extends AbstractODFSignatureService {

	private static final Log LOG = LogFactory
			.getLog(SignatureServiceBean.class);

	private final TemporaryDataStorage temporaryDataStorage;

	@EJB
	private ODFTempFileManager odfTempFileManager;

	public SignatureServiceBean() {
		LOG.debug("constructor");
		this.temporaryDataStorage = new HttpSessionTemporaryDataStorage();
	}

	@Override
	protected URL getOpenDocumentURL() {
		return this.odfTempFileManager.getTempFile();
	}

	@Override
	protected OutputStream getSignedOpenDocumentOutputStream() {
		LOG.debug("get signed ODF output stream");
		// TODO implement me
		LOG.debug("TODO: implement me");
		return new ByteArrayOutputStream();
	}

	@Override
	protected TemporaryDataStorage getTemporaryDataStorage() {
		return this.temporaryDataStorage;
	}
}
