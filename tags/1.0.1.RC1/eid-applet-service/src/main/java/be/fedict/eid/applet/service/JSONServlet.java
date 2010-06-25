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
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
		JSONObject eidJSONObject = new JSONObject();

		JSONObject identityJSONObject = new JSONObject();
		eidJSONObject.put("identity", identityJSONObject);
		Identity identity = eIdData.identity;
		identityJSONObject.put("nationalNumber", identity.nationalNumber);
		identityJSONObject.put("name", identity.name);
		identityJSONObject.put("firstName", identity.firstName);
		identityJSONObject.put("middleName", identity.middleName);
		identityJSONObject.put("dateOfBirth", identity.dateOfBirth.getTime()
				.toString());
		identityJSONObject.put("placeOfBirth", identity.placeOfBirth);
		identityJSONObject.put("gender", identity.gender);

		JSONObject cardJSONObject = new JSONObject();
		eidJSONObject.put("card", cardJSONObject);
		cardJSONObject.put("cardNumber", identity.cardNumber);
		cardJSONObject.put("chipNumber", identity.chipNumber);
		cardJSONObject.put("cardDeliveryMunicipality",
				identity.cardDeliveryMunicipality);
		cardJSONObject.put("cardValidityDateBegin",
				identity.cardValidityDateBegin.getTime().toString());
		cardJSONObject.put("cardValidityDateEnd", identity.cardValidityDateEnd
				.getTime().toString());

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
			JSONObject authnCertJSONObject = new JSONObject();
			certsJSONObject.put("authn", authnCertJSONObject);
			authnCertJSONObject.put("subject", authnCertificate
					.getSubjectX500Principal().toString());
			authnCertJSONObject.put("issuer", authnCertificate
					.getIssuerX500Principal().toString());
			authnCertJSONObject.put("serialNumber", authnCertificate
					.getSerialNumber().toString());
			authnCertJSONObject.put("notBefore", authnCertificate
					.getNotBefore().toString());
			authnCertJSONObject.put("notAfter", authnCertificate.getNotAfter()
					.toString());
			authnCertJSONObject.put("signatureAlgo", authnCertificate
					.getSigAlgName());
			authnCertJSONObject.put("thumbprint", DigestUtils
					.shaHex(authnCertificate.getEncoded()));
		}

		eidJSONObject.writeJSONString(writer);
	}
}
