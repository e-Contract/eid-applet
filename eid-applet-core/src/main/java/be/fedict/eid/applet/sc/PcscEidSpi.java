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

	/**
	 * Gives back a list of all available smart card readers.
	 * 
	 * @return
	 */
	List<String> getReaderList();

	byte[] readFile(byte[] fileId) throws Exception;

	void close();

	/**
	 * Checks whether there is an eID card present in one of the available smart
	 * card readers.
	 * 
	 * @return
	 * @throws Exception
	 */
	boolean isEidPresent() throws Exception;

	/**
	 * Checks whether there is a smart card reader available on the system.
	 * 
	 * @return
	 * @throws Exception
	 */
	boolean hasCardReader() throws Exception;

	/**
	 * Wait until a smart card reader has been connected to the system.
	 * 
	 * @throws Exception
	 */
	void waitForCardReader() throws Exception;

	/**
	 * Waits for an eID card to be present in one of the available smart card
	 * readers.
	 * 
	 * @throws Exception
	 */
	void waitForEidPresent() throws Exception;

	/**
	 * Waits until (some) smart card has been removed from some smart card
	 * reader.
	 * 
	 * @throws Exception
	 */
	void removeCard() throws Exception;

	/**
	 * Change the PIN code of the eID card. The PIN will be queried to the
	 * citizen via some GUI dialog.
	 * 
	 * @throws Exception
	 */
	void changePin() throws Exception;

	/**
	 * Unblock the eID card. The PUK1 and PUK2 codes will be queried to the
	 * citizen via some GUI dialog.
	 * 
	 * @throws Exception
	 */
	void unblockPin() throws Exception;

	/**
	 * Creates an authentication signature.
	 * 
	 * @param toBeSigned
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws CardException
	 * @throws IOException
	 */
	byte[] signAuthn(byte[] toBeSigned) throws NoSuchAlgorithmException,
			CardException, IOException;

	/**
	 * Creates a non-repudiation signature starting from a hashed value of the
	 * data to be signed.
	 * 
	 * @param digestValue
	 * @param digestAlgo
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws CardException
	 * @throws IOException
	 */
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

	/**
	 * Adds an observer for eID file readout progress monitoring.
	 * 
	 * @param observer
	 */
	void addObserver(Observer observer);

	/**
	 * Log-off the eID card that's present in the named smart card reader.
	 * 
	 * @param readerName
	 *            the PC/SC name of the smart card reader.
	 * @throws Exception
	 */
	void logoff(String readerName) throws Exception;

	/**
	 * Selects the BELPIC JavaCard Applet on the active eID card.
	 */
	void selectBelpicJavaCardApplet();
}