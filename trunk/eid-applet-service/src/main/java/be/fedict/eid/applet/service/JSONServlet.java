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

package be.fedict.eid.applet.service;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.json.simple.JSONObject;

/**
 * Servlet to retrieve the eID identity data from the HTTP session context via
 * JSON.
 * 
 * @author Frank Cornelis
 */
public class JSONServlet extends HttpServlet {

	private static final Log LOG = LogFactory.getLog(JSONServlet.class);

	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		LOG.debug("doGet");
		HttpSession httpSession = request.getSession();
		EIdData eIdData = (EIdData) httpSession.getAttribute("eid");
		if (null == eIdData) {
			throw new ServletException("no eID data available");
		}
		PrintWriter writer = response.getWriter();
		try {
			outputJSON(eIdData, writer);
		} catch (CertificateEncodingException e) {
			throw new ServletException("Certificate encoding error: "
					+ e.getMessage(), e);
		}
	}

	public static void outputJSON(EIdData eIdData, PrintWriter writer)
			throws IOException, CertificateEncodingException {
		SimpleDateFormat simpleDateFormat = new SimpleDateFormat("MM/dd/yyyy");

		JSONObject eidJSONObject = new JSONObject();

		JSONObject identityJSONObject = new JSONObject();
		eidJSONObject.put("identity", identityJSONObject);
		Identity identity = eIdData.identity;
		identityJSONObject.put("nationalNumber", identity.nationalNumber);
		identityJSONObject.put("name", identity.name);
		identityJSONObject.put("firstName", identity.firstName);
		identityJSONObject.put("middleName", identity.middleName);
		identityJSONObject.put("dateOfBirth", simpleDateFormat
				.format(identity.dateOfBirth.getTime()));
		identityJSONObject.put("placeOfBirth", identity.placeOfBirth);
		identityJSONObject.put("gender", identity.gender.toString());

		JSONObject cardJSONObject = new JSONObject();
		eidJSONObject.put("card", cardJSONObject);
		cardJSONObject.put("cardNumber", identity.cardNumber);
		cardJSONObject.put("chipNumber", identity.chipNumber);
		cardJSONObject.put("cardDeliveryMunicipality",
				identity.cardDeliveryMunicipality);
		cardJSONObject.put("cardValidityDateBegin", simpleDateFormat
				.format(identity.cardValidityDateBegin.getTime()));
		cardJSONObject.put("cardValidityDateEnd", simpleDateFormat
				.format(identity.cardValidityDateEnd.getTime()));

		Address address = eIdData.address;
		if (null != address) {
			JSONObject addressJSONObject = new JSONObject();
			eidJSONObject.put("address", addressJSONObject);
			addressJSONObject.put("streetAndNumber", address.streetAndNumber);
			addressJSONObject.put("municipality", address.municipality);
			addressJSONObject.put("zip", address.zip);
		}

		EIdCertsData certsData = eIdData.certs;
		if (null != certsData) {
			JSONObject certsJSONObject = new JSONObject();
			eidJSONObject.put("certs", certsJSONObject);

			X509Certificate authnCertificate = certsData.authn;
			JSONObject authnCertJSONObject = createCertJSONObject(
					authnCertificate, simpleDateFormat);
			certsJSONObject.put("authn", authnCertJSONObject);

			X509Certificate signCertificate = certsData.sign;
			JSONObject signCertJSONObject = createCertJSONObject(
					signCertificate, simpleDateFormat);
			certsJSONObject.put("sign", signCertJSONObject);

			X509Certificate citizenCACertificate = certsData.ca;
			JSONObject citizenCACertJSONObject = createCertJSONObject(
					citizenCACertificate, simpleDateFormat);
			certsJSONObject.put("citizenCA", citizenCACertJSONObject);

			X509Certificate rootCACertificate = certsData.root;
			JSONObject rootCACertJSONObject = createCertJSONObject(
					rootCACertificate, simpleDateFormat);
			certsJSONObject.put("rootCA", rootCACertJSONObject);
		}

		eidJSONObject.writeJSONString(writer);
	}

	private static JSONObject createCertJSONObject(X509Certificate certificate,
			SimpleDateFormat simpleDateFormat)
			throws CertificateEncodingException, IOException {
		JSONObject certJSONObject = new JSONObject();
		certJSONObject.put("subject", certificate.getSubjectX500Principal()
				.toString());
		certJSONObject.put("issuer", certificate.getIssuerX500Principal()
				.toString());
		certJSONObject.put("serialNumber", certificate.getSerialNumber()
				.toString());
		certJSONObject.put("notBefore", certificate.getNotBefore().toString());
		certJSONObject.put("notAfter", certificate.getNotAfter().toString());
		certJSONObject.put("signatureAlgo", certificate.getSigAlgName());
		certJSONObject.put("thumbprint", DigestUtils.shaHex(certificate
				.getEncoded()));
		certJSONObject.put("details", certificate.toString());
		certJSONObject.put("pem", toPem(certificate));

		return certJSONObject;
	}

	private static String toPem(X509Certificate certificate) throws IOException {
		StringWriter stringWriter = new StringWriter();
		PEMWriter pemWriter = new PEMWriter(stringWriter,
				BouncyCastleProvider.PROVIDER_NAME);
		pemWriter.writeObject(certificate);
		pemWriter.close();
		return stringWriter.toString();
	}
}
