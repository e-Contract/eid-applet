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

package be.fedict.eid.applet.sc;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Observer;

import javax.smartcardio.CardException;

/**
 * Java 5 PC/SC eID component Service Provider Interface.
 * 
 * @author fcorneli
 * 
 */
public interface PcscEidSpi {

	List<String> getReaderList();

	byte[] readFile(byte[] fileId) throws Exception;

	void close();

	boolean isEidPresent() throws Exception;

	void waitForEidPresent() throws Exception;

	void removeCard() throws Exception;

	void changePin() throws Exception;

	void unblockPin() throws Exception;

	byte[] signAuthn(byte[] toBeSigned) throws NoSuchAlgorithmException,
			CardException, IOException;

	byte[] sign(byte[] digestValue, String digestAlgo)
			throws NoSuchAlgorithmException, CardException, IOException;

	List<X509Certificate> getAuthnCertificateChain() throws CardException,
			IOException, CertificateException;

	List<X509Certificate> getSignCertificateChain() throws CardException,
			IOException, CertificateException;

	/**
	 * De-authenticate.
	 * 
	 * @throws Exception
	 */
	void logoff() throws Exception;

	void addObserver(Observer observer);

	void logoff(String readerName) throws Exception;

	void selectBelpicJavaCardApplet();
}