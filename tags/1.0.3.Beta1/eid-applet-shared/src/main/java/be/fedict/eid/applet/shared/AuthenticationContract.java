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

package be.fedict.eid.applet.shared;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;

/**
 * Authentication Contract class.
 * 
 * <p>
 * Volgens artikel 4, paragraaf 5 van de wet van 9 juli 2001 betreffende het
 * juridisch kader voor elektronische handtekeningen en certificatiediensten kan
 * de rechtsgeldigheid van elektronische handtekeningen niet worden ontzegd op
 * grond van het feit dat de handtekening niet is gebaseerd op een
 * gekwalificeerd certificaat. Hieruit kan men afleiden dat cryptografische
 * handtekeningen, gemaakt met het authenticatie certificaat, tevens als
 * rechtsgeldige elektronische handtekeningen kunnen worden geïnterpreteerd.
 * </p>
 * 
 * <p>
 * This class allows a citizen to proof that the cryptographic signature created
 * with his authentication certificate was indeed meant as way of
 * authenticating. In case of challenge abuse, there was no intention to sign
 * any legally binding contract except this authentication contract. If a
 * malicious eID Applet Service tricks the citizen into signing a document
 * digest instead of a meaningless challenge, we give the citizen a proof of
 * intention via this formal authentication contract.
 * </p>
 * 
 * @author Frank Cornelis
 * 
 */
public class AuthenticationContract {

	private final byte[] salt;

	private final String hostname;

	private final InetAddress inetAddress;

	public static final String LEGAL_NOTICE = "Declaration of authentication intension.\n"
			+ "The following data should be interpreted as an authentication challenge.\n";

	private final byte[] sessionId;

	private final byte[] encodedServerCertificate;

	private final byte[] challenge;

	/**
	 * Main constructor.
	 * 
	 * @param salt
	 * @param hostname
	 *            the optional hostname.
	 * @param inetAddress
	 *            the optional internet address.
	 * @param sessionId
	 *            the optional SSL session identifier.
	 * @param encodedServerCertificate
	 *            the optional DER encoded X509 server certificate.
	 * @param challenge
	 */
	public AuthenticationContract(byte[] salt, String hostname,
			InetAddress inetAddress, byte[] sessionId,
			byte[] encodedServerCertificate, byte[] challenge) {
		this.salt = salt;
		this.hostname = hostname;
		this.inetAddress = inetAddress;
		this.sessionId = sessionId;
		this.encodedServerCertificate = encodedServerCertificate;
		this.challenge = challenge;
	}

	public byte[] calculateToBeSigned() throws IOException {
		ByteArrayOutputStream toBeSignedOutputStream = new ByteArrayOutputStream();
		/*
		 * Salting prevents that we sign a document digest directly instead of
		 * some meaningless challenge.
		 */
		toBeSignedOutputStream.write(this.salt);
		if (null != this.hostname) {
			/*
			 * Signing (salt||hostname||challenge) prevents man-in-the-middle
			 * attacks from websites for which the SSL certificate is still
			 * trusted but that have been compromised. If at the same time the
			 * DNS is also attacked, well then everything is lost anyway.
			 */
			toBeSignedOutputStream.write(this.hostname.getBytes());
		}
		if (null != this.inetAddress) {
			byte[] address = this.inetAddress.getAddress();
			toBeSignedOutputStream.write(address);
		}
		/*
		 * Next is to prevent abuse of the challenge in the context of a digital
		 * signature claim on this cryptographic authentication signature.
		 */
		toBeSignedOutputStream.write(LEGAL_NOTICE.getBytes());
		if (null != this.sessionId) {
			toBeSignedOutputStream.write(this.sessionId);
		}
		if (null != this.encodedServerCertificate) {
			toBeSignedOutputStream.write(this.encodedServerCertificate);
		}
		/*
		 * Of course we also digest the challenge as the server needs some mean
		 * to authenticate us.
		 */
		toBeSignedOutputStream.write(this.challenge);
		byte[] toBeSigned = toBeSignedOutputStream.toByteArray();
		return toBeSigned;
	}
}
