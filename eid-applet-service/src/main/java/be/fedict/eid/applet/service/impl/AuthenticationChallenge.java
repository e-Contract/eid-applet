/*
 * eID Applet Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2014 e-Contract.be BVBA.
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

import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Date;

import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Authentication Challenge. Manages challenge freshness and randomness.
 * 
 * @author Frank Cornelis
 * 
 */
public class AuthenticationChallenge implements Serializable {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(AuthenticationChallenge.class);

	public static final String AUTHN_CHALLENGE_SESSION_ATTRIBUTE = AuthenticationChallenge.class
			.getName();

	/**
	 * The default maximum allowed maturity of the challenge in milliseconds.
	 */
	public static final long DEFAULT_MAX_MATURITY = 1000 * 60 * 5;

	private final byte[] challenge;

	private final Date timestamp;

	private static final SecureRandom secureRandom;

	static {
		secureRandom = new SecureRandom();
		/*
		 * We put some initial seed.
		 */
		secureRandom.setSeed(System.currentTimeMillis());
	}

	private AuthenticationChallenge() {
		/*
		 * Since SHA-1 is 20 bytes, we also take 20 here. More bytes wouldn't
		 * bring us anything.
		 */
		this.challenge = new byte[20];
		secureRandom.nextBytes(this.challenge);
		/*
		 * Next should make it pretty non-deterministic.
		 */
		secureRandom.setSeed(System.currentTimeMillis());
		this.timestamp = new Date();
	}

	/**
	 * Generates a challenge and stores it in the given HTTP session for later
	 * consumption.
	 * 
	 * @param session
	 * @return the challenge.
	 */
	public static byte[] generateChallenge(HttpSession session) {
		AuthenticationChallenge authenticationChallenge = new AuthenticationChallenge();
		if (null != session.getAttribute(AUTHN_CHALLENGE_SESSION_ATTRIBUTE)) {
			LOG.warn("overwriting a previous authentication challenge");
		}
		session.setAttribute(AUTHN_CHALLENGE_SESSION_ATTRIBUTE,
				authenticationChallenge);
		byte[] challenge = authenticationChallenge.getChallenge();
		return challenge;
	}

	private byte[] getChallenge() {
		/*
		 * This method indeed is private. We want controlled consumption of the
		 * authentication challenge.
		 */
		return this.challenge;
	}

	private Date getTimestamp() {
		return this.timestamp;
	}

	/**
	 * Gives back the authentication challenge. This challenge is checked for
	 * freshness and can be consumed only once.
	 * 
	 * @param session
	 * @param maxMaturity
	 * @return
	 */
	public static byte[] getAuthnChallenge(HttpSession session, Long maxMaturity) {
		AuthenticationChallenge authenticationChallenge = (AuthenticationChallenge) session
				.getAttribute(AUTHN_CHALLENGE_SESSION_ATTRIBUTE);
		if (null == authenticationChallenge) {
			throw new SecurityException("no challenge in session");
		}
		session.removeAttribute(AUTHN_CHALLENGE_SESSION_ATTRIBUTE);
		Date now = new Date();
		if (null == maxMaturity) {
			maxMaturity = DEFAULT_MAX_MATURITY;
		}
		long dt = now.getTime()
				- authenticationChallenge.getTimestamp().getTime();
		if (dt > maxMaturity) {
			throw new SecurityException("maximum challenge maturity reached");
		}
		byte[] challenge = authenticationChallenge.getChallenge();
		return challenge;
	}

	/**
	 * Gives back the authentication challenge. This challenge is checked for
	 * freshness and can be consumed only once.
	 * 
	 * @param session
	 * @return
	 */
	public static byte[] getAuthnChallenge(HttpSession session) {
		return getAuthnChallenge(session, null);
	}
}
