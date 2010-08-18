/*
 * eID Applet Project.
 * Copyright (C) 2010 FedICT.
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

package be.fedict.eid.applet.service.signer.time;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.ByteArrayRequestEntity;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.RequestEntity;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

import be.fedict.eid.applet.service.signer.facets.RevocationData;

/**
 * A TSP time-stamp service implementation.
 * 
 * @author Frank Cornelis
 * 
 */
public class TSPTimeStampService implements TimeStampService {

	private static final Log LOG = LogFactory.getLog(TSPTimeStampService.class);

	static {
		if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	public static final String DEFAULT_USER_AGENT = "eID Applet Service TSP Client";

	private final String tspServiceUrl;

	private final String requestPolicy;

	private final String userAgent;

	private final TimeStampServiceValidator validator;

	private String username;

	private String password;

	private String proxyHost;

	private int proxyPort;

	private String digestAlgo;

	private String digestAlgoOid;

	public TSPTimeStampService(String tspServiceUrl,
			TimeStampServiceValidator validator) {
		this(tspServiceUrl, validator, null, null);
	}

	/**
	 * Main constructor.
	 * 
	 * @param tspServiceUrl
	 *            the URL of the TSP service.
	 * @param validator
	 *            the trust validator used to validate incoming TSP response
	 *            signatures.
	 * @param requestPolicy
	 *            the optional TSP request policy.
	 * @param userAgent
	 *            the optional User-Agent TSP request header value.
	 */
	public TSPTimeStampService(String tspServiceUrl,
			TimeStampServiceValidator validator, String requestPolicy,
			String userAgent) {
		if (null == tspServiceUrl) {
			throw new IllegalArgumentException("TSP service URL required");
		}
		this.tspServiceUrl = tspServiceUrl;

		if (null == validator) {
			throw new IllegalArgumentException("TSP validator required");
		}
		this.validator = validator;

		this.requestPolicy = requestPolicy;

		if (null != userAgent) {
			this.userAgent = userAgent;
		} else {
			this.userAgent = DEFAULT_USER_AGENT;
		}

		this.digestAlgo = "SHA-1";
		this.digestAlgoOid = TSPAlgorithms.SHA1;
	}

	/**
	 * Sets the credentials used in case the TSP service requires
	 * authentication.
	 * 
	 * @param username
	 * @param password
	 */
	public void setAuthenticationCredentials(String username, String password) {
		this.username = username;
		this.password = password;
	}

	public void resetAuthenticationCredentials() {
		this.username = null;
		this.password = null;
	}

	/**
	 * Sets the digest algorithm used for time-stamping data. Example value:
	 * "SHA-1".
	 * 
	 * @param digestAlgo
	 */
	public void setDigestAlgo(String digestAlgo) {
		if ("SHA-1".equals(digestAlgo)) {
			this.digestAlgoOid = TSPAlgorithms.SHA1;
		} else if ("SHA-256".equals(digestAlgo)) {
			this.digestAlgoOid = TSPAlgorithms.SHA256;
		} else if ("SHA-384".equals(digestAlgo)) {
			this.digestAlgoOid = TSPAlgorithms.SHA384;
		} else if ("SHA-512".equals(digestAlgo)) {
			this.digestAlgoOid = TSPAlgorithms.SHA512;
		} else {
			throw new IllegalArgumentException("unsupported digest algo: "
					+ digestAlgo);
		}
		this.digestAlgo = digestAlgo;
	}

	/**
	 * Configures the HTTP proxy settings to be used to connect to the TSP
	 * service.
	 * 
	 * @param proxyHost
	 * @param proxyPort
	 */
	public void setProxy(String proxyHost, int proxyPort) {
		this.proxyHost = proxyHost;
		this.proxyPort = proxyPort;
	}

	public void resetProxy() {
		this.proxyHost = null;
		this.proxyPort = 0;
	}

	public byte[] timeStamp(byte[] data, RevocationData revocationData)
			throws Exception {
		// digest the message
		MessageDigest messageDigest = MessageDigest
				.getInstance(this.digestAlgo);
		byte[] digest = messageDigest.digest(data);

		// generate the TSP request
		BigInteger nonce = new BigInteger(128, new SecureRandom());
		TimeStampRequestGenerator requestGenerator = new TimeStampRequestGenerator();
		requestGenerator.setCertReq(true);
		if (null != this.requestPolicy) {
			requestGenerator.setReqPolicy(this.requestPolicy);
		}
		TimeStampRequest request = requestGenerator.generate(
				this.digestAlgoOid, digest, nonce);
		byte[] encodedRequest = request.getEncoded();

		// create the HTTP client
		HttpClient httpClient = new HttpClient();
		if (null != this.username) {
			Credentials credentials = new UsernamePasswordCredentials(
					this.username, this.password);
			httpClient.getState().setCredentials(AuthScope.ANY, credentials);
		}
		if (null != this.proxyHost) {
			httpClient.getHostConfiguration().setProxy(this.proxyHost,
					this.proxyPort);
		}

		// create the HTTP POST request
		PostMethod postMethod = new PostMethod(this.tspServiceUrl);
		RequestEntity requestEntity = new ByteArrayRequestEntity(
				encodedRequest, "application/timestamp-query");
		postMethod.addRequestHeader("User-Agent", this.userAgent);
		postMethod.setRequestEntity(requestEntity);

		// invoke TSP service
		int statusCode = httpClient.executeMethod(postMethod);
		if (HttpStatus.SC_OK != statusCode) {
			LOG.error("Error contacting TSP server " + this.tspServiceUrl);
			throw new Exception("Error contacting TSP server "
					+ this.tspServiceUrl);
		}

		// HTTP input validation
		Header responseContentTypeHeader = postMethod
				.getResponseHeader("Content-Type");
		if (null == responseContentTypeHeader) {
			throw new RuntimeException("missing Content-Type header");
		}
		String contentType = responseContentTypeHeader.getValue();
		if (!contentType.startsWith("application/timestamp-reply")) {
			LOG.debug("response content: "
					+ postMethod.getResponseBodyAsString());
			throw new RuntimeException("invalid Content-Type: " + contentType);
		}
		if (0 == postMethod.getResponseContentLength()) {
			throw new RuntimeException("Content-Length is zero");
		}

		// TSP response parsing and validation
		InputStream inputStream = postMethod.getResponseBodyAsStream();
		TimeStampResponse timeStampResponse = new TimeStampResponse(inputStream);
		timeStampResponse.validate(request);

		if (0 != timeStampResponse.getStatus()) {
			LOG.debug("status: " + timeStampResponse.getStatus());
			LOG.debug("status string: " + timeStampResponse.getStatusString());
			PKIFailureInfo failInfo = timeStampResponse.getFailInfo();
			if (null != failInfo) {
				LOG.debug("fail info int value: " + failInfo.intValue());
				if (PKIFailureInfo.unacceptedPolicy == failInfo.intValue()) {
					LOG.debug("unaccepted policy");
				}
			}
			throw new RuntimeException("timestamp response status != 0: "
					+ timeStampResponse.getStatus());
		}
		TimeStampToken timeStampToken = timeStampResponse.getTimeStampToken();
		SignerId signerId = timeStampToken.getSID();
		BigInteger signerCertSerialNumber = signerId.getSerialNumber();
		X500Principal signerCertIssuer = signerId.getIssuer();
		LOG.debug("signer cert serial number: " + signerCertSerialNumber);
		LOG.debug("signer cert issuer: " + signerCertIssuer);

		// TSP signer certificates retrieval
		CertStore certStore = timeStampToken.getCertificatesAndCRLs(
				"Collection", BouncyCastleProvider.PROVIDER_NAME);
		Collection<? extends Certificate> certificates = certStore
				.getCertificates(null);
		X509Certificate signerCert = null;
		Map<String, X509Certificate> certificateMap = new HashMap<String, X509Certificate>();
		for (Certificate certificate : certificates) {
			X509Certificate x509Certificate = (X509Certificate) certificate;
			if (signerCertIssuer.equals(x509Certificate
					.getIssuerX500Principal())
					&& signerCertSerialNumber.equals(x509Certificate
							.getSerialNumber())) {
				signerCert = x509Certificate;
			}
			String ski = Hex.encodeHexString(getSubjectKeyId(x509Certificate));
			certificateMap.put(ski, x509Certificate);
			LOG.debug("embedded certificate: "
					+ x509Certificate.getSubjectX500Principal() + "; SKI="
					+ ski);
		}

		// TSP signer cert path building
		if (null == signerCert) {
			throw new RuntimeException(
					"TSP response token has no signer certificate");
		}
		List<X509Certificate> tspCertificateChain = new LinkedList<X509Certificate>();
		X509Certificate certificate = signerCert;
		do {
			LOG.debug("adding to certificate chain: "
					+ certificate.getSubjectX500Principal());
			tspCertificateChain.add(certificate);
			if (certificate.getSubjectX500Principal().equals(
					certificate.getIssuerX500Principal())) {
				break;
			}
			String aki = Hex.encodeHexString(getAuthorityKeyId(certificate));
			certificate = certificateMap.get(aki);
		} while (null != certificate);

		// verify TSP signer signature
		timeStampToken.validate(tspCertificateChain.get(0),
				BouncyCastleProvider.PROVIDER_NAME);

		// verify TSP signer certificate
		this.validator.validate(tspCertificateChain, revocationData);

		LOG.debug("time-stamp token time: "
				+ timeStampToken.getTimeStampInfo().getGenTime());

		byte[] timestamp = timeStampToken.getEncoded();
		return timestamp;
	}

	private byte[] getSubjectKeyId(X509Certificate cert) throws IOException {
		byte[] extvalue = cert
				.getExtensionValue(X509Extensions.SubjectKeyIdentifier.getId());
		if (extvalue == null) {
			return null;
		}
		ASN1OctetString str = ASN1OctetString.getInstance(new ASN1InputStream(
				new ByteArrayInputStream(extvalue)).readObject());
		SubjectKeyIdentifier keyId = SubjectKeyIdentifier
				.getInstance(new ASN1InputStream(new ByteArrayInputStream(str
						.getOctets())).readObject());
		return keyId.getKeyIdentifier();
	}

	private byte[] getAuthorityKeyId(X509Certificate cert) throws IOException {
		byte[] extvalue = cert
				.getExtensionValue(X509Extensions.AuthorityKeyIdentifier
						.getId());
		if (extvalue == null) {
			return null;
		}
		DEROctetString oct = (DEROctetString) (new ASN1InputStream(
				new ByteArrayInputStream(extvalue)).readObject());
		AuthorityKeyIdentifier keyId = new AuthorityKeyIdentifier(
				(ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(oct
						.getOctets())).readObject());
		return keyId.getKeyIdentifier();
	}
}