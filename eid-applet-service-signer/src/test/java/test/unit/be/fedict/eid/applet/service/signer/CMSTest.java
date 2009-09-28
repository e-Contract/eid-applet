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

package test.unit.be.fedict.eid.applet.service.signer;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.joda.time.DateTime;
import org.junit.BeforeClass;
import org.junit.Test;

public class CMSTest {

	private static final Log LOG = LogFactory.getLog(CMSTest.class);

	@BeforeClass
	public static void beforeClass() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testPkcs1Signature() throws Exception {
		// setup
		KeyPair keyPair = generateKeyPair();
		byte[] toBeSigned = "hello world".getBytes();

		// operate
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(toBeSigned);
		byte[] signatureValue = signature.sign();

		// verify
		signature.initVerify(keyPair.getPublic());
		signature.update(toBeSigned);
		boolean signatureResult = signature.verify(signatureValue);
		assertTrue(signatureResult);
	}

	/**
	 * CMS signature with external data and external certificate. The CMS only
	 * contains the signature and some certificate selector.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testBasicCmsSignature() throws Exception {
		// setup
		KeyPair keyPair = generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = generateSelfSignedCertificate(keyPair,
				"CN=Test", notBefore, notAfter);
		byte[] toBeSigned = "hello world".getBytes();

		// operate
		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
		generator.addSigner(keyPair.getPrivate(), certificate,
				CMSSignedDataGenerator.DIGEST_SHA1);
		CMSProcessable content = new CMSProcessableByteArray(toBeSigned);
		CMSSignedData signedData = generator.generate(content, false, null);

		byte[] cmsSignature = signedData.getEncoded();
		LOG.debug("CMS signature: "
				+ ASN1Dump.dumpAsString(new ASN1StreamParser(cmsSignature)
						.readObject()));

		// verify
		signedData = new CMSSignedData(content, cmsSignature);
		SignerInformationStore signers = signedData.getSignerInfos();
		Iterator<SignerInformation> iter = signers.getSigners().iterator();
		while (iter.hasNext()) {
			SignerInformation signer = iter.next();
			SignerId signerId = signer.getSID();
			LOG.debug("signer: " + signerId);
			assertTrue(signerId.match(certificate));
			assertTrue(signer.verify(keyPair.getPublic(),
					BouncyCastleProvider.PROVIDER_NAME));
		}
		LOG.debug("content type: " + signedData.getSignedContentTypeOID());
	}

	/**
	 * CMS signature with embedded data and external certificate. The CMS only
	 * contains the original content, signature and some certificate selector.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testCmsSignatureWithContent() throws Exception {
		// setup
		KeyPair keyPair = generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = generateSelfSignedCertificate(keyPair,
				"CN=Test", notBefore, notAfter);
		byte[] toBeSigned = "hello world".getBytes();

		// operate
		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
		generator.addSigner(keyPair.getPrivate(), certificate,
				CMSSignedDataGenerator.DIGEST_SHA1);
		CMSProcessable content = new CMSProcessableByteArray(toBeSigned);
		CMSSignedData signedData = generator.generate(content, true, null);

		byte[] cmsSignature = signedData.getEncoded();
		LOG.debug("CMS signature: "
				+ ASN1Dump.dumpAsString(new ASN1StreamParser(cmsSignature)
						.readObject()));

		// verify
		signedData = new CMSSignedData(cmsSignature);
		SignerInformationStore signers = signedData.getSignerInfos();
		Iterator<SignerInformation> iter = signers.getSigners().iterator();
		while (iter.hasNext()) {
			SignerInformation signer = iter.next();
			SignerId signerId = signer.getSID();
			LOG.debug("signer: " + signerId);
			assertTrue(signerId.match(certificate));
			assertTrue(signer.verify(keyPair.getPublic(),
					BouncyCastleProvider.PROVIDER_NAME));
		}
		byte[] data = (byte[]) signedData.getSignedContent().getContent();
		assertArrayEquals(toBeSigned, data);
		LOG.debug("content type: " + signedData.getSignedContentTypeOID());
	}

	/**
	 * CMS signature with external data and embedded certificate. The CMS only
	 * contains the signature, signing certificate and some certificate
	 * selector.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testCmsSignatureWithCertificate() throws Exception {
		// setup
		KeyPair keyPair = generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = generateSelfSignedCertificate(keyPair,
				"CN=Test", notBefore, notAfter);
		byte[] toBeSigned = "hello world".getBytes();

		// operate
		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
		/*
		 * addSigner requires the certificate to be able to calculate the key
		 * selector.
		 */
		generator.addSigner(keyPair.getPrivate(), certificate,
				CMSSignedDataGenerator.DIGEST_SHA1);
		List<X509Certificate> certList = new LinkedList<X509Certificate>();
		certList.add(certificate);
		CertStore certStore = CertStore.getInstance("Collection",
				new CollectionCertStoreParameters(certList));
		generator.addCertificatesAndCRLs(certStore);
		CMSProcessable content = new CMSProcessableByteArray(toBeSigned);
		CMSSignedData signedData = generator.generate(content, false, null);

		byte[] cmsSignature = signedData.getEncoded();
		LOG.debug("CMS signature: "
				+ ASN1Dump.dumpAsString(new ASN1StreamParser(cmsSignature)
						.readObject()));

		// verify
		signedData = new CMSSignedData(content, cmsSignature);
		certStore = signedData.getCertificatesAndCRLs("Collection",
				BouncyCastleProvider.PROVIDER_NAME);
		SignerInformationStore signers = signedData.getSignerInfos();
		Iterator<SignerInformation> iter = signers.getSigners().iterator();
		while (iter.hasNext()) {
			SignerInformation signer = iter.next();
			SignerId signerId = signer.getSID();
			LOG.debug("signer: " + signerId);
			assertTrue(signerId.match(certificate));
			assertTrue(signer.verify(keyPair.getPublic(),
					BouncyCastleProvider.PROVIDER_NAME));
			X509Certificate storedCert = (X509Certificate) certStore
					.getCertificates(signerId).iterator().next();
			assertEquals(certificate, storedCert);
		}
		LOG.debug("content type: " + signedData.getSignedContentTypeOID());
	}

	private KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = new SecureRandom();
		keyPairGenerator.initialize(new RSAKeyGenParameterSpec(1024,
				RSAKeyGenParameterSpec.F4), random);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	private X509Certificate generateSelfSignedCertificate(KeyPair keyPair,
			String subjectDn, DateTime notBefore, DateTime notAfter)
			throws IOException, InvalidKeyException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException, CertificateException {
		PublicKey subjectPublicKey = keyPair.getPublic();
		PrivateKey issuerPrivateKey = keyPair.getPrivate();
		String signatureAlgorithm = "SHA1WithRSAEncryption";
		X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
		certificateGenerator.reset();
		certificateGenerator.setPublicKey(subjectPublicKey);
		certificateGenerator.setSignatureAlgorithm(signatureAlgorithm);
		certificateGenerator.setNotBefore(notBefore.toDate());
		certificateGenerator.setNotAfter(notAfter.toDate());
		X509Principal issuerDN = new X509Principal(subjectDn);
		certificateGenerator.setIssuerDN(issuerDN);
		certificateGenerator.setSubjectDN(new X509Principal(subjectDn));
		certificateGenerator.setSerialNumber(new BigInteger(128,
				new SecureRandom()));

		certificateGenerator.addExtension(X509Extensions.SubjectKeyIdentifier,
				false, createSubjectKeyId(subjectPublicKey));
		PublicKey issuerPublicKey;
		issuerPublicKey = subjectPublicKey;
		certificateGenerator.addExtension(
				X509Extensions.AuthorityKeyIdentifier, false,
				createAuthorityKeyId(issuerPublicKey));

		certificateGenerator.addExtension(X509Extensions.BasicConstraints,
				false, new BasicConstraints(true));

		X509Certificate certificate;
		certificate = certificateGenerator.generate(issuerPrivateKey);

		/*
		 * Next certificate factory trick is needed to make sure that the
		 * certificate delivered to the caller is provided by the default
		 * security provider instead of BouncyCastle. If we don't do this trick
		 * we might run into trouble when trying to use the CertPath validator.
		 */
		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(certificate
						.getEncoded()));
		return certificate;
	}

	private SubjectKeyIdentifier createSubjectKeyId(PublicKey publicKey)
			throws IOException {
		ByteArrayInputStream bais = new ByteArrayInputStream(publicKey
				.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				(ASN1Sequence) new ASN1InputStream(bais).readObject());
		return new SubjectKeyIdentifier(info);
	}

	private AuthorityKeyIdentifier createAuthorityKeyId(PublicKey publicKey)
			throws IOException {

		ByteArrayInputStream bais = new ByteArrayInputStream(publicKey
				.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				(ASN1Sequence) new ASN1InputStream(bais).readObject());

		return new AuthorityKeyIdentifier(info);
	}
}
