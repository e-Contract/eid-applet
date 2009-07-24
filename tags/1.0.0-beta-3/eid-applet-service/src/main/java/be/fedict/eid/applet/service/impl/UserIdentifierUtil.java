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

package be.fedict.eid.applet.service.impl;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Utility class for user identifier construction.
 * 
 * @author fcorneli
 * 
 */
public class UserIdentifierUtil {

	private static final Log LOG = LogFactory.getLog(UserIdentifierUtil.class);

	private UserIdentifierUtil() {
		super();
	}

	/**
	 * Gives back a unique user identifier given an X509 certificate.
	 * 
	 * @param signingCertificate
	 * @return
	 */
	public static String getUserId(X509Certificate signingCertificate) {
		X500Principal userPrincipal = signingCertificate
				.getSubjectX500Principal();
		String name = userPrincipal.toString();
		int serialNumberBeginIdx = name.indexOf("SERIALNUMBER=");
		if (-1 == serialNumberBeginIdx) {
			throw new SecurityException("SERIALNUMBER not found in X509 CN");
		}
		int serialNumberValueBeginIdx = serialNumberBeginIdx
				+ "SERIALNUMBER=".length();
		int serialNumberValueEndIdx = name.indexOf(",",
				serialNumberValueBeginIdx);
		if (-1 == serialNumberValueEndIdx) {
			serialNumberValueEndIdx = name.length();
		}
		String userId = name.substring(serialNumberValueBeginIdx,
				serialNumberValueEndIdx);
		return userId;
	}

	public static final String HMAC_ALGO = "HmacSHA1";

	/**
	 * Gives back a non-reversible citizen identifier (NRCID).
	 * 
	 * @param userId
	 *            the primary user identifier, i.e. the national registry
	 *            number.
	 * @param orgId
	 *            the optional organization identifier.
	 * @param appId
	 *            the optional application identifier.
	 * @param secret
	 *            the application specific secret. Should be at least 128 bit
	 *            long. Encoded in hexadecimal format.
	 * @return
	 */
	public static String getNonReversibleCitizenIdentifier(String userId,
			String orgId, String appId, String secret) {
		if (null == secret) {
			throw new IllegalArgumentException("secret key is null");
		}
		/*
		 * Avoid XML formatting issues introduced by some web.xml XML editors.
		 */
		secret = secret.trim();
		if (null != orgId) {
			orgId = orgId.trim();
		} else {
			LOG.warn("it is advised to use an orgId");
		}
		if (null != appId) {
			appId = appId.trim();
		} else {
			LOG.warn("it is advised to use an appId");
		}

		/*
		 * Decode the secret key.
		 */
		byte[] secretKey;
		try {
			secretKey = Hex.decodeHex(secret.toCharArray());
		} catch (DecoderException e) {
			LOG.error("secret is not hexadecimal encoded: " + e.getMessage());
			throw new IllegalArgumentException(
					"secret is not hexadecimal encoded");
		}
		if ((128 / 8) > secretKey.length) {
			/*
			 * 128 bit is seen as secure these days.
			 */
			LOG.warn("secret key is too short");
			throw new IllegalArgumentException("secret key is too short");
		}

		/*
		 * Construct the HMAC input sequence.
		 */
		String input = userId;
		if (null != appId) {
			input += appId;
		}
		if (null != orgId) {
			input += orgId;
		}
		byte[] inputData = input.getBytes();

		SecretKey macKey = new SecretKeySpec(secretKey, HMAC_ALGO);
		Mac mac;
		try {
			mac = Mac.getInstance(macKey.getAlgorithm());
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("HMAC algo not available: "
					+ e.getMessage());
		}
		try {
			mac.init(macKey);
		} catch (InvalidKeyException e) {
			LOG.error("invalid secret key: " + e.getMessage(), e);
			throw new RuntimeException("invalid secret");
		}
		mac.update(inputData);
		byte[] resultHMac = mac.doFinal();
		String resultHex = new String(Hex.encodeHex(resultHMac)).toUpperCase();
		return resultHex;
	}
}
