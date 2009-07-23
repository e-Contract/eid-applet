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

package test.be.fedict.eid.applet;

import static org.junit.Assert.assertEquals;

import java.awt.Component;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Locale;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.swing.JOptionPane;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.commons.httpclient.protocol.SSLProtocolSocketFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mortbay.jetty.security.SslSocketConnector;
import org.mortbay.jetty.testing.ServletTester;

import be.fedict.eid.applet.Messages;
import be.fedict.eid.applet.Status;
import be.fedict.eid.applet.View;
import be.fedict.eid.applet.sc.Pkcs11Eid;

public class SslTest {
	private static final Log LOG = LogFactory.getLog(SslTest.class);

	private ServletTester servletTester;

	private String sslLocation;

	private int sslPort;

	private KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = new SecureRandom();
		keyPairGenerator.initialize(new RSAKeyGenParameterSpec(1024,
				RSAKeyGenParameterSpec.F4), random);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
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

	private void persistKey(File pkcs12keyStore, PrivateKey privateKey,
			X509Certificate certificate, char[] keyStorePassword,
			char[] keyEntryPassword) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore keyStore = KeyStore.getInstance("pkcs12");
		keyStore.load(null, keyStorePassword);
		keyStore.setKeyEntry("default", privateKey, keyEntryPassword,
				new Certificate[] { certificate });
		FileOutputStream keyStoreOut = new FileOutputStream(pkcs12keyStore);
		keyStore.store(keyStoreOut, keyStorePassword);
		keyStoreOut.close();
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

	private static int getFreePort() throws Exception {
		ServerSocket serverSocket = new ServerSocket(0);
		int port = serverSocket.getLocalPort();
		serverSocket.close();
		return port;
	}

	public static class TestServlet extends HttpServlet {

		private static final long serialVersionUID = 1L;

		@Override
		protected void doGet(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			LOG.debug("doGet");
			PrintWriter writer = response.getWriter();
			writer.println("hello world");
			writer.flush();
			writer.close();
		}
	}

	private Messages messages;

	@Before
	public void setUp() throws Exception {
		this.messages = new Messages(Locale.getDefault());

		this.servletTester = new ServletTester();
		this.servletTester.addServlet(TestServlet.class, "/");

		Security.addProvider(new BouncyCastleProvider());

		KeyPair keyPair = generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = generateSelfSignedCertificate(keyPair,
				"CN=localhost", notBefore, notAfter);
		File tmpP12File = File.createTempFile("ssl-", ".p12");
		LOG.debug("p12 file: " + tmpP12File.getAbsolutePath());
		persistKey(tmpP12File, keyPair.getPrivate(), certificate, "secret"
				.toCharArray(), "secret".toCharArray());

		SslSocketConnector sslSocketConnector = new SslSocketConnector();
		sslSocketConnector.setKeystore(tmpP12File.getAbsolutePath());
		sslSocketConnector.setTruststore(tmpP12File.getAbsolutePath());
		sslSocketConnector.setTruststoreType("pkcs12");
		sslSocketConnector.setKeystoreType("pkcs12");
		sslSocketConnector.setPassword("secret");
		sslSocketConnector.setKeyPassword("secret");
		sslSocketConnector.setTrustPassword("secret");
		sslSocketConnector.setMaxIdleTime(30000);
		sslSocketConnector.setNeedClientAuth(true);
		this.sslPort = getFreePort();
		sslSocketConnector.setPort(this.sslPort);
		this.servletTester.getContext().getServer().addConnector(
				sslSocketConnector);
		this.sslLocation = "https://localhost:" + this.sslPort + "/";

		this.servletTester.start();

		SSLContext sslContext = SSLContext.getInstance("TLS");
		TrustManager trustManager = new TestTrustManager(certificate);
		KeyManager keyManager = new TestKeyManager(this.messages);
		sslContext.init(new KeyManager[] { keyManager },
				new TrustManager[] { trustManager }, null);
		SSLContext.setDefault(sslContext);
	}

	private static class TestView implements View {

		private static final Log LOG = LogFactory.getLog(TestView.class);

		@Override
		public void addDetailMessage(String detailMessage) {
			LOG.debug("detail message: " + detailMessage);
		}

		@Override
		public Component getParentComponent() {
			return null;
		}

		@Override
		public boolean privacyQuestion(boolean includeAddress,
				boolean includePhoto) {
			return false;
		}

		@Override
		public void progressIndication(int max, int current) {
		}

		@Override
		public void setStatusMessage(Status status, String statusMessage) {
			LOG.debug("status [" + status + "] " + statusMessage);
		}
	}

	private static class TestKeyManager implements X509KeyManager {

		private static final Log LOG = LogFactory.getLog(TestKeyManager.class);

		Pkcs11Eid pkcs11Eid = null;

		private static final String ALIAS = "eID";

		private final Messages messages;

		public TestKeyManager(Messages messages) {
			this.messages = messages;
		}

		@Override
		public String chooseClientAlias(String[] keyType, Principal[] issuers,
				Socket socket) {
			LOG.debug("chooseClientAlias");
			return ALIAS;
		}

		@Override
		public String chooseServerAlias(String keyType, Principal[] issuers,
				Socket socket) {
			LOG.debug("chooseServerAlias");
			return null;
		}

		private PrivateKeyEntry privateKeyEntry;

		@Override
		public X509Certificate[] getCertificateChain(String alias) {
			LOG.debug("getCertificateChain: " + alias);
			try {
				if (true == ALIAS.equals(alias)) {
					if (null != this.pkcs11Eid) {
						this.pkcs11Eid.close();
					} else {
						this.pkcs11Eid = new Pkcs11Eid(new TestView(),
								this.messages);
					}
					if (false == this.pkcs11Eid.isEidPresent()) {
						LOG.debug("insert eID card...");
						this.pkcs11Eid.waitForEidPresent();
					}
					this.privateKeyEntry = this.pkcs11Eid.getPrivateKeyEntry();
					return (X509Certificate[]) this.privateKeyEntry
							.getCertificateChain();
				}
			} catch (Exception e) {
				LOG.error("error: " + e.getMessage(), e);
				return null;
			}
			return null;
		}

		@Override
		public String[] getClientAliases(String keyType, Principal[] issuers) {
			LOG.debug("getClientAliases");
			return null;
		}

		@Override
		public PrivateKey getPrivateKey(String alias) {
			LOG.debug("getPrivateKey: " + alias);
			if (ALIAS.equals(alias)) {
				return this.privateKeyEntry.getPrivateKey();
			}
			return null;
		}

		@Override
		public String[] getServerAliases(String keyType, Principal[] issuers) {
			LOG.debug("getServerAliases");
			return null;
		}
	}

	private static class TestTrustManager implements X509TrustManager {

		private static final Log LOG = LogFactory
				.getLog(TestTrustManager.class);

		private final X509Certificate serverCertificate;

		public TestTrustManager(X509Certificate serverCertificate) {
			this.serverCertificate = serverCertificate;
		}

		public void checkClientTrusted(X509Certificate[] chain, String authnType)
				throws CertificateException {
			LOG.debug("check client trusted: " + chain[0]);
		}

		public void checkServerTrusted(X509Certificate[] chain, String authnType)
				throws CertificateException {
			LOG.debug("check server trusted");
			if (false == this.serverCertificate.equals(chain[0])) {
				throw new CertificateException("server certificate not trusted");
			}
		}

		public X509Certificate[] getAcceptedIssuers() {
			LOG.debug("getAcceptedIssuers");
			return null;
		}
	}

	@After
	public void tearDown() throws Exception {
		this.servletTester.stop();
	}

	@Test
	public void connection() throws Exception {
		LOG.debug("URL: " + this.sslLocation);

		JOptionPane.showMessageDialog(null, "URL: " + this.sslLocation);

		HttpClient httpClient = new HttpClient();
		GetMethod getMethod = new GetMethod(this.sslLocation);

		Protocol.registerProtocol("ssl", new Protocol("https",
				(ProtocolSocketFactory) new SSLProtocolSocketFactory(),
				this.sslPort));

		int statusCode = httpClient.executeMethod(getMethod);
		LOG.debug("status code: " + statusCode);
		assertEquals(HttpServletResponse.SC_OK, statusCode);
		String response = getMethod.getResponseBodyAsString();
		LOG.debug("response: " + response);
	}
}
