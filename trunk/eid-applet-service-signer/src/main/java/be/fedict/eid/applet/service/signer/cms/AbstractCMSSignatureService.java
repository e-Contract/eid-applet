/*
 * eID Applet Project.
 * Copyright (C) 2009-2010 FedICT.
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

package be.fedict.eid.applet.service.signer.cms;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;

import be.fedict.eid.applet.service.signer.DummyPrivateKey;
import be.fedict.eid.applet.service.signer.SHA1WithRSAProxySignature;
import be.fedict.eid.applet.service.spi.DigestInfo;
import be.fedict.eid.applet.service.spi.SignatureService;

/**
 * Abstract CMS Signature Service class. The content and signing certificate are
 * included in the CMS signature.
 * 
 * @author Frank Cornelis
 * 
 */
public abstract class AbstractCMSSignatureService implements SignatureService {

	public String getFilesDigestAlgorithm() {
		return null;
	}

	public DigestInfo preSign(List<DigestInfo> digestInfos,
			List<X509Certificate> signingCertificateChain)
			throws NoSuchAlgorithmException {
		CMSSignedDataGenerator generator = createCMSSignedDataGenerator(signingCertificateChain);
		byte[] toBeSigned = getToBeSigned();
		CMSProcessable content = new CMSProcessableByteArray(toBeSigned);

		CMSProvider provider = new CMSProvider();
		SHA1WithRSAProxySignature.reset();
		try {
			generator.generate(content, true, provider);
		} catch (CMSException e) {
			throw new RuntimeException(e);
		}
		byte[] digestValue = SHA1WithRSAProxySignature.getDigestValue();
		String description = getSignatureDescription();
		DigestInfo digestInfo = new DigestInfo(digestValue, "SHA1", description);
		return digestInfo;
	}

	public void postSign(byte[] signatureValue,
			List<X509Certificate> signingCertificateChain) {
		CMSSignedDataGenerator generator;
		try {
			generator = createCMSSignedDataGenerator(signingCertificateChain);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}

		byte[] toBeSigned = getToBeSigned();
		CMSProcessable content = new CMSProcessableByteArray(toBeSigned);

		CMSProvider provider = new CMSProvider();
		SHA1WithRSAProxySignature.reset();
		SHA1WithRSAProxySignature.setSignatureValue(signatureValue);
		CMSSignedData signedData;
		try {
			signedData = generator.generate(content, true, provider);
		} catch (CMSException e) {
			throw new RuntimeException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		byte[] cmsSignature;
		try {
			cmsSignature = signedData.getEncoded();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		this.storeCMSSignature(cmsSignature);
	}

	private CMSSignedDataGenerator createCMSSignedDataGenerator(
			List<X509Certificate> signingCertificateChain)
			throws NoSuchAlgorithmException {
		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
		if (null != signingCertificateChain) {
			X509Certificate signerCertificate = signingCertificateChain.get(0);
			PrivateKey dummyPrivateKey = new DummyPrivateKey();
			generator.addSigner(dummyPrivateKey, signerCertificate,
					CMSSignedDataGenerator.DIGEST_SHA1);
			List<X509Certificate> certList = new LinkedList<X509Certificate>();
			certList.add(signerCertificate);
			CertStore certStore;
			try {
				certStore = CertStore.getInstance("Collection",
						new CollectionCertStoreParameters(certList));
			} catch (InvalidAlgorithmParameterException e) {
				throw new NoSuchAlgorithmException(e);
			}
			try {
				generator.addCertificatesAndCRLs(certStore);
			} catch (CertStoreException e) {
				throw new RuntimeException(e);
			} catch (CMSException e) {
				throw new RuntimeException(e);
			}
		}
		return generator;
	}

	abstract protected byte[] getToBeSigned();

	abstract protected String getSignatureDescription();

	abstract protected void storeCMSSignature(byte[] cmsSignature);
}
