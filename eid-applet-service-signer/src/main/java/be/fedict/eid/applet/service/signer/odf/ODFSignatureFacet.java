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

package be.fedict.eid.applet.service.signer.odf;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import be.fedict.eid.applet.service.signer.DigestAlgo;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import be.fedict.eid.applet.service.signer.SignatureFacet;

/**
 * Signature Facet implementation to create ODF signatures.
 * 
 * @author fcorneli
 * 
 */
public class ODFSignatureFacet implements SignatureFacet {

	private static final Log LOG = LogFactory.getLog(ODFSignatureFacet.class);

	private final AbstractODFSignatureService signatureService;
    private final DigestAlgo digestAlgo;

	public ODFSignatureFacet(AbstractODFSignatureService signatureService,
                             DigestAlgo digestAlgo) {
		this.signatureService = signatureService;
        this.digestAlgo = digestAlgo;
	}

	public void postSign(Element signatureElement,
			List<X509Certificate> signingCertificateChain) {
		// empty
	}

	public void preSign(XMLSignatureFactory signatureFactory,
			Document document, String signatureId,
			List<X509Certificate> signingCertificateChain,
			List<Reference> references, List<XMLObject> objects)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		try {
			URL odfUrl = this.signatureService.getOpenDocumentURL();
			InputStream odfInputStream = odfUrl.openStream();
			ZipInputStream odfZipInputStream = new ZipInputStream(
					odfInputStream);
			ZipEntry zipEntry;

			DigestMethod digestMethod = signatureFactory.newDigestMethod(
					this.digestAlgo.getXmlAlgoId(), null);

			while (null != (zipEntry = odfZipInputStream.getNextEntry())) {
				if (ODFUtil.isToBeSigned(zipEntry)) {
					String name = zipEntry.getName();
					/*
					 * Whitespaces are illegal in URIs
					 * 
					 * Note that OOo 3.0/3.1 seems to have a bug, seems like the
					 * OOo signature verification doesn't convert it back to
					 * whitespace, to be investigated
					 */
					String uri = name.replaceAll(" ", "%20");

					Reference reference;
					if (name.endsWith(".xml") && !isEmpty(odfZipInputStream)) {
						/* apply transformation on non-empty XML files only */
						List<Transform> transforms = new LinkedList<Transform>();
						Transform transform = signatureFactory.newTransform(
								CanonicalizationMethod.INCLUSIVE,
								(TransformParameterSpec) null);
						transforms.add(transform);
						reference = signatureFactory.newReference(uri,
								digestMethod, transforms, null, null);
					} else {
						reference = signatureFactory.newReference(uri,
								digestMethod);
					}
					references.add(reference);
					LOG.debug("entry: " + name);
				}
			}
		} catch (IOException e) {
			LOG.error("IO error: " + e.getMessage(), e);
		} catch (Exception e) {
			LOG.error("Error: " + e.getMessage(), e);
		}
	}

	/**
	 * Unfortunately zipEntry.getSize() often returns -1/size unknown, so this
	 * is a quick hack to see if the file is empty or not
	 * 
	 * @param inputStream
	 * @return
	 * @throws IOException
	 */
	private boolean isEmpty(InputStream inputStream) throws IOException {
		return 0 == inputStream.skip(1);
	}
}
