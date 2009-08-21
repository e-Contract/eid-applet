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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Local;
import javax.ejb.Stateless;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.ejb3.annotation.LocalBinding;

import be.fedict.eid.applet.service.signer.HttpSessionTemporaryDataStorage;
import be.fedict.eid.applet.service.signer.TemporaryDataStorage;
import be.fedict.eid.applet.service.signer.odf.AbstractODFSignatureService;
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

	private static final String TMP_SIGNED_ODF = "signedOdfUrl";

	private final TemporaryDataStorage temporaryDataStorage;

	@EJB
	private ODFTempFileManager odfTempFileManager;

	public SignatureServiceBean() {
		LOG.debug("constructor");
		this.temporaryDataStorage = new HttpSessionTemporaryDataStorage();
	}

	@Override
	protected URL getOpenDocumentURL() {
		return this.odfTempFileManager
				.getTempFile(ODFTempFileManager.ODF_URL_SESSION_ATTRIBUTE);
	}

	@Override
	protected OutputStream getSignedOpenDocumentOutputStream() {
		LOG.debug("get signed ODF output stream");
		try {
			URL tmpSignedOdfUrl = this.odfTempFileManager
					.createTempFile(TMP_SIGNED_ODF);
			File tmpSignedOdfFile = new File(tmpSignedOdfUrl.toURI());
			FileOutputStream outputStream = new FileOutputStream(
					tmpSignedOdfFile);
			return outputStream;
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage(), e);
		} catch (URISyntaxException e) {
			throw new RuntimeException("URI error: " + e.getMessage(), e);
		}
	}

	@Override
	public void postSign(byte[] signatureValue,
			List<X509Certificate> signingCertificateChain) {
		super.postSign(signatureValue, signingCertificateChain);
		LOG.debug("after super post sign");
		URL tmpSignedOdfUrl = this.odfTempFileManager
				.getTempFile(TMP_SIGNED_ODF);
		LOG.debug("tmp signed ODF url: " + tmpSignedOdfUrl);
		URL odfUrl = this.odfTempFileManager
				.getTempFile(ODFTempFileManager.ODF_URL_SESSION_ATTRIBUTE);
		File odfFile;
		try {
			odfFile = new File(odfUrl.toURI());
		} catch (URISyntaxException e) {
			throw new RuntimeException("URI error");
		}
		OutputStream outputStream;
		try {
			outputStream = new FileOutputStream(odfFile);
		} catch (FileNotFoundException e) {
			throw new RuntimeException("FileNotFoundException error");
		}
		try {
			IOUtils.copy(tmpSignedOdfUrl.openStream(), outputStream);
		} catch (IOException e) {
			throw new RuntimeException("IOException error");
		}
	}

	@Override
	protected TemporaryDataStorage getTemporaryDataStorage() {
		return this.temporaryDataStorage;
	}
}
