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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import be.fedict.eid.applet.Messages;
import be.fedict.eid.applet.View;

import sun.security.pkcs11.SunPKCS11;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_INFO;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.CK_SLOT_INFO;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

/**
 * Class holding all PKCS#11 eID card access logic.
 * 
 * @author fcorneli
 * 
 */
public class Pkcs11Eid {

	public static final byte[] SHA1_DIGEST_INFO_PREFIX = new byte[] { 0x30,
			0x1f, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x04,
			0x14 };

	public static final byte[] SHA224_DIGEST_INFO_PREFIX = new byte[] { 0x30,
			0x2b, 0x30, 0x0b, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65,
			0x03, 0x04, 0x02, 0x04, 0x04, 0x1c };

	public static final byte[] SHA256_DIGEST_INFO_PREFIX = new byte[] { 0x30,
			0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65,
			0x03, 0x04, 0x02, 0x01, 0x04, 0x20 };

	public static final byte[] SHA384_DIGEST_INFO_PREFIX = new byte[] { 0x30,
			0x3f, 0x30, 0x0b, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65,
			0x03, 0x04, 0x02, 0x02, 0x04, 0x30 };

	public static final byte[] SHA512_DIGEST_INFO_PREFIX = new byte[] { 0x30,
			0x4f, 0x30, 0x0b, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65,
			0x03, 0x04, 0x02, 0x03, 0x04, 0x40 };

	public static final byte[] RIPEMD160_DIGEST_INFO_PREFIX = new byte[] {
			0x30, 0x1f, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x01,
			0x04, 0x14 };

	public static final byte[] RIPEMD128_DIGEST_INFO_PREFIX = new byte[] {
			0x30, 0x1b, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x02,
			0x04, 0x10 };

	public static final byte[] RIPEMD256_DIGEST_INFO_PREFIX = new byte[] {
			0x30, 0x2b, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x03,
			0x04, 0x20 };

	private final View view;

	private PKCS11 pkcs11;

	private long slotIdx;

	private String slotDescription;

	private Messages messages;

	public Pkcs11Eid(View view, Messages messages) {
		this.view = view;
		this.messages = messages;
	}

	/**
	 * Gives back the PKCS11 wrapper. This is just for debugging purposes.
	 * 
	 * @return
	 */
	public PKCS11 getPkcs11() {
		return this.pkcs11;
	}

	private String getPkcs11Path() throws PKCS11NotFoundException {
		String osName = System.getProperty("os.name");
		File pkcs11File;
		if (osName.startsWith("Linux")) {
			/*
			 * Covers 3.5 eID Middleware.
			 */
			pkcs11File = new File("/usr/local/lib/libbeidpkcs11.so");
			if (pkcs11File.exists()) {
				return pkcs11File.getAbsolutePath();
			}
			/*
			 * Some 2.6 eID MW installations.
			 */
			pkcs11File = new File("/usr/lib/libbeidpkcs11.so");
			if (pkcs11File.exists()) {
				return pkcs11File.getAbsolutePath();
			}
			/*
			 * Some 2.6 and 2.5.9 installations.
			 */
			pkcs11File = new File("/usr/local/lib/pkcs11/Belgium-EID-pkcs11.so");
			if (pkcs11File.exists()) {
				return pkcs11File.getAbsolutePath();
			}
			/*
			 * Final fallback is OpenSC. Note that OpenSC PKCS#11 cannot create
			 * non-rep signatures.
			 * 
			 * /etc/opensc.conf:
			 * 
			 * card_drivers = belpic, ...
			 * 
			 * reader_driver pcsc {}
			 */
			pkcs11File = new File("/usr/lib/opensc-pkcs11.so");
			if (pkcs11File.exists()) {
				return pkcs11File.getAbsolutePath();
			}
		} else if (osName.startsWith("Mac")) {
			/*
			 * eID MW 3.5.1
			 */
			pkcs11File = new File("/usr/local/lib/libbeidpkcs11.3.5.1.dylib");
			if (pkcs11File.exists()) {
				return pkcs11File.getAbsolutePath();
			}
			/*
			 * eID MW 3.5
			 */
			pkcs11File = new File("/usr/local/lib/libbeidpkcs11.3.5.0.dylib");
			if (pkcs11File.exists()) {
				return pkcs11File.getAbsolutePath();
			}
			/*
			 * eID MW 2.6
			 */
			pkcs11File = new File(
					"/usr/local/lib/beid-pkcs11.bundle/Contents/MacOS/libbeidpkcs11.2.1.0.dylib");
			if (pkcs11File.exists()) {
				return pkcs11File.getAbsolutePath();
			}
			/*
			 * We try the symbolic links only at the end since there were some
			 * negative reports on the symbolic links on Mac installations.
			 */
			/*
			 * eID MW 3.x series
			 */
			pkcs11File = new File("/usr/local/lib/libbeidpkcs11.dylib");
			if (pkcs11File.exists()) {
				return pkcs11File.getAbsolutePath();
			}
			/*
			 * eID MW 2.x series
			 */
			pkcs11File = new File(
					"/usr/local/lib/beid-pkcs11.bundle/Contents/MacOS/libbeidpkcs11.dylib");
			if (pkcs11File.exists()) {
				return pkcs11File.getAbsolutePath();
			}
		} else {
			/*
			 * eID Middleware 3.5 - XP
			 */
			pkcs11File = new File("C:\\WINDOWS\\system32\\beidpkcs11.dll");
			if (pkcs11File.exists()) {
				return pkcs11File.getAbsolutePath();
			}
			/*
			 * eID Middleware 2.6 and 2.5.9
			 */
			pkcs11File = new File(
					"C:\\WINDOWS\\system32\\Belgium Identity Card PKCS11.dll");
			if (pkcs11File.exists()) {
				return pkcs11File.getAbsolutePath();
			}
			/*
			 * Windows 2000.
			 */
			pkcs11File = new File(
					"C:\\WINNT\\system32\\Belgium Identity Card PKCS11.dll");
			if (pkcs11File.exists()) {
				return pkcs11File.getAbsolutePath();
			}
			pkcs11File = new File("C:\\WINNT\\system32\\beidpkcs11.dll");
			if (pkcs11File.exists()) {
				return pkcs11File.getAbsolutePath();
			}
		}
		throw new PKCS11NotFoundException();
	}

	private PKCS11 loadPkcs11(String pkcs11Path)
			throws IllegalArgumentException, IllegalAccessException,
			InvocationTargetException, SecurityException, NoSuchMethodException {
		try {
			/*
			 * Java 1.6
			 */
			Method getInstanceMethod = PKCS11.class.getMethod("getInstance",
					String.class, String.class, CK_C_INITIALIZE_ARGS.class,
					Boolean.TYPE);
			CK_C_INITIALIZE_ARGS ck_c_initialize_args = new CK_C_INITIALIZE_ARGS();
			PKCS11 pkcs11 = (PKCS11) getInstanceMethod.invoke(null, pkcs11Path,
					"C_GetFunctionList", ck_c_initialize_args, false);
			return pkcs11;
		} catch (NoSuchMethodException e) {
			/*
			 * Java 1.5
			 */
			this.view.addDetailMessage("PKCS11 getInstance Java 1.5 fallback");
			Method getInstanceMethod = PKCS11.class.getMethod("getInstance",
					String.class, CK_C_INITIALIZE_ARGS.class, Boolean.TYPE);
			PKCS11 pkcs11 = (PKCS11) getInstanceMethod.invoke(null, pkcs11Path,
					null, false);
			return pkcs11;
		}
	}

	public List<String> getReaderList() throws PKCS11NotFoundException,
			IllegalArgumentException, SecurityException,
			IllegalAccessException, InvocationTargetException,
			NoSuchMethodException, PKCS11Exception, NoSuchFieldException {
		List<String> readerList = new LinkedList<String>();
		String pkcs11Path = getPkcs11Path();
		this.pkcs11 = loadPkcs11(pkcs11Path);
		long[] slotIdxs = this.pkcs11.C_GetSlotList(false);
		for (long slotIdx : slotIdxs) {
			CK_SLOT_INFO slotInfo = this.pkcs11.C_GetSlotInfo(slotIdx);
			String reader = new String(slotInfo.slotDescription).trim();
			readerList.add(reader);
		}
		cFinalize();
		return readerList;
	}

	public boolean isEidPresent() throws IOException, PKCS11Exception,
			InterruptedException, NoSuchFieldException, IllegalAccessException,
			IllegalArgumentException, SecurityException,
			InvocationTargetException, NoSuchMethodException {
		String pkcs11Path = getPkcs11Path();
		this.view.addDetailMessage("PKCS#11 path: " + pkcs11Path);
		this.pkcs11 = loadPkcs11(pkcs11Path);
		CK_INFO ck_info = this.pkcs11.C_GetInfo();
		this.view.addDetailMessage("library description: "
				+ new String(ck_info.libraryDescription).trim());
		this.view.addDetailMessage("manufacturer ID: "
				+ new String(ck_info.manufacturerID).trim());
		this.view.addDetailMessage("library version: "
				+ Integer.toString(ck_info.libraryVersion.major, 16) + "."
				+ Integer.toString(ck_info.libraryVersion.minor, 16));
		this.view.addDetailMessage("cryptoki version: "
				+ Integer.toString(ck_info.cryptokiVersion.major, 16) + "."
				+ Integer.toString(ck_info.cryptokiVersion.minor, 16));
		long[] slotIdxs = this.pkcs11.C_GetSlotList(false);
		if (0 == slotIdxs.length) {
			this.view.addDetailMessage("no card readers connected?");
		}
		for (long slotIdx : slotIdxs) {
			CK_SLOT_INFO slotInfo = this.pkcs11.C_GetSlotInfo(slotIdx);
			this.view.addDetailMessage("reader: "
					+ new String(slotInfo.slotDescription).trim());
			if ((slotInfo.flags & PKCS11Constants.CKF_TOKEN_PRESENT) != 0) {
				CK_TOKEN_INFO tokenInfo;
				try {
					tokenInfo = this.pkcs11.C_GetTokenInfo(slotIdx);
				} catch (PKCS11Exception e) {
					/*
					 * Can occur when someone just removed the eID card.
					 * CKR_TOKEN_NOT_PRESENT.
					 */
					continue;
				}
				if (new String(tokenInfo.label).startsWith("BELPIC")) {
					this.view.addDetailMessage("Belgium eID card in slot: "
							+ slotIdx);
					this.slotIdx = slotIdx;
					this.slotDescription = new String(slotInfo.slotDescription)
							.trim();
					return true;
				}
			}
		}
		cFinalize();
		return false;
	}

	public String getSlotDescription() {
		return this.slotDescription;
	}

	private void cFinalize() throws PKCS11Exception, NoSuchFieldException,
			IllegalAccessException {
		this.pkcs11.C_Finalize(null);
		Field moduleMapField = PKCS11.class.getDeclaredField("moduleMap");
		moduleMapField.setAccessible(true);
		Map<?, ?> moduleMap = (Map<?, ?>) moduleMapField.get(null);
		moduleMap.clear(); // force re-execution of C_Initialize next time
		this.pkcs11 = null;
	}

	/**
	 * Wait for eID card presence in some token slot.
	 * 
	 * @throws IOException
	 * @throws PKCS11Exception
	 * @throws InterruptedException
	 * @throws NoSuchFieldException
	 * @throws IllegalAccessException
	 * @throws NoSuchMethodException
	 * @throws InvocationTargetException
	 * @throws SecurityException
	 * @throws IllegalArgumentException
	 */
	public void waitForEidPresent() throws IOException, PKCS11Exception,
			InterruptedException, NoSuchFieldException, IllegalAccessException,
			IllegalArgumentException, SecurityException,
			InvocationTargetException, NoSuchMethodException {
		while (true) {
			if (true == isEidPresent()) {
				return;
			}
			Thread.sleep(1000);
		}
	}

	private SunPKCS11 pkcs11Provider;

	public PrivateKeyEntry getPrivateKeyEntry() throws IOException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException,
			UnrecoverableEntryException {
		// setup configuration file
		File tmpConfigFile = File.createTempFile("pkcs11-", "conf");
		tmpConfigFile.deleteOnExit();
		PrintWriter configWriter = new PrintWriter(new FileOutputStream(
				tmpConfigFile), true);
		configWriter.println("name=SmartCard");
		configWriter.println("library=" + getPkcs11Path());
		configWriter.println("slotListIndex= " + this.slotIdx);

		// load security provider
		this.pkcs11Provider = new SunPKCS11(tmpConfigFile.getAbsolutePath());
		if (-1 == Security.addProvider(this.pkcs11Provider)) {
			throw new RuntimeException("could not add security provider");
		}

		// load key material
		KeyStore keyStore = KeyStore.getInstance("PKCS11", this.pkcs11Provider);
		LoadStoreParameter loadStoreParameter = new Pkcs11LoadStoreParameter(
				this.view, this.messages);
		keyStore.load(loadStoreParameter);
		Enumeration<String> aliases = keyStore.aliases();
		while (aliases.hasMoreElements()) {
			/*
			 * Apparently the first eID cards have some issue with the PKCS#15
			 * structure causing problems in the PKCS#11 object listing.
			 */
			String alias = aliases.nextElement();
			this.view.addDetailMessage("key alias: " + alias);
		}
		String alias = "Authentication";
		PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry(
				alias, null);
		if (null == privateKeyEntry) {
			/*
			 * Seems like this can happen for very old eID cards.
			 */
			throw new RuntimeException(
					"private key entry for alias not found: " + alias);
		}
		return privateKeyEntry;
	}

	public byte[] signAuthn(byte[] toBeSigned) throws IOException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException,
			UnrecoverableEntryException, InvalidKeyException,
			SignatureException {
		PrivateKeyEntry privateKeyEntry = getPrivateKeyEntry();
		PrivateKey privateKey = privateKeyEntry.getPrivateKey();
		X509Certificate[] certificateChain = (X509Certificate[]) privateKeyEntry
				.getCertificateChain();
		this.authnCertificateChain = new LinkedList<X509Certificate>();
		for (X509Certificate certificate : certificateChain) {
			this.authnCertificateChain.add(certificate);
		}

		// create signature
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(privateKey);
		signature.update(toBeSigned);
		byte[] signatureValue = signature.sign();
		return signatureValue;
	}

	private List<X509Certificate> authnCertificateChain;

	public List<X509Certificate> getAuthnCertificateChain() {
		return this.authnCertificateChain;
	}

	private List<X509Certificate> signCertificateChain;

	public List<X509Certificate> getSignCertificateChain() {
		return this.signCertificateChain;
	}

	public void close() throws PKCS11Exception, NoSuchFieldException,
			IllegalAccessException {
		if (null != this.pkcs11Provider) {
			Security.removeProvider(this.pkcs11Provider.getName());
			this.pkcs11Provider = null;
		}
		cFinalize();
	}

	public void removeCard() throws PKCS11Exception, InterruptedException {
		while (true) {
			CK_SLOT_INFO slotInfo = this.pkcs11.C_GetSlotInfo(this.slotIdx);
			if ((slotInfo.flags & PKCS11Constants.CKF_TOKEN_PRESENT) == 0) {
				return;
			}
			/*
			 * We want to be quite responsive here.
			 */
			Thread.sleep(100);
		}
	}

	public byte[] sign(byte[] digestValue, String digestAlgo) throws Exception {
		/*
		 * We sign directly via the PKCS#11 wrapper since this is the only way
		 * to sign the given digest value.
		 */
		long session = this.pkcs11.C_OpenSession(this.slotIdx,
				PKCS11Constants.CKF_SERIAL_SESSION, null, null);
		byte[] signatureValue;
		try {
			CK_ATTRIBUTE[] attributes = new CK_ATTRIBUTE[2];
			attributes[0] = new CK_ATTRIBUTE();
			attributes[0].type = PKCS11Constants.CKA_CLASS;
			attributes[0].pValue = PKCS11Constants.CKO_PRIVATE_KEY;
			attributes[1] = new CK_ATTRIBUTE();
			attributes[1].type = PKCS11Constants.CKA_LABEL;
			attributes[1].pValue = "Signature";
			this.pkcs11.C_FindObjectsInit(session, attributes);
			long[] keyHandles = this.pkcs11.C_FindObjects(session, 1);
			long keyHandle = keyHandles[0];
			this.view.addDetailMessage("key handle: " + keyHandle);
			this.pkcs11.C_FindObjectsFinal(session);

			CK_MECHANISM mechanism = new CK_MECHANISM();
			mechanism.mechanism = PKCS11Constants.CKM_RSA_PKCS;
			mechanism.pParameter = null;
			this.pkcs11.C_SignInit(session, mechanism, keyHandle);

			ByteArrayOutputStream digestInfo = new ByteArrayOutputStream();
			if ("SHA-1".equals(digestAlgo) || "SHA1".equals(digestAlgo)) {
				digestInfo.write(SHA1_DIGEST_INFO_PREFIX);
			} else if ("SHA-224".equals(digestAlgo)) {
				digestInfo.write(SHA224_DIGEST_INFO_PREFIX);
			} else if ("SHA-256".equals(digestAlgo)) {
				digestInfo.write(SHA256_DIGEST_INFO_PREFIX);
			} else if ("SHA-384".equals(digestAlgo)) {
				digestInfo.write(SHA384_DIGEST_INFO_PREFIX);
			} else if ("SHA-512".equals(digestAlgo)) {
				digestInfo.write(SHA512_DIGEST_INFO_PREFIX);
			} else if ("RIPEMD160".equals(digestAlgo)) {
				digestInfo.write(RIPEMD160_DIGEST_INFO_PREFIX);
			} else if ("RIPEMD128".equals(digestAlgo)) {
				digestInfo.write(RIPEMD128_DIGEST_INFO_PREFIX);
			} else if ("RIPEMD256".equals(digestAlgo)) {
				digestInfo.write(RIPEMD256_DIGEST_INFO_PREFIX);
			} else {
				throw new RuntimeException("digest also not supported: "
						+ digestAlgo);
			}
			digestInfo.write(digestValue);

			signatureValue = pkcs11.C_Sign(session, digestInfo.toByteArray());
		} finally {
			this.pkcs11.C_CloseSession(session);
		}

		/*
		 * We use the Sun JCE to construct the certificate path.
		 */
		// setup configuration file
		File tmpConfigFile = File.createTempFile("pkcs11-", "conf");
		tmpConfigFile.deleteOnExit();
		PrintWriter configWriter = new PrintWriter(new FileOutputStream(
				tmpConfigFile), true);
		configWriter.println("name=SmartCard");
		configWriter.println("library=" + getPkcs11Path());
		configWriter.println("slotListIndex= " + this.slotIdx);

		// load security provider
		this.pkcs11Provider = new SunPKCS11(tmpConfigFile.getAbsolutePath());
		if (-1 == Security.addProvider(this.pkcs11Provider)) {
			throw new RuntimeException("could not add security provider");
		}

		// load key material
		KeyStore keyStore = KeyStore.getInstance("PKCS11", this.pkcs11Provider);
		keyStore.load(null, null);
		String alias = "Signature";
		PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry(
				alias, null);
		if (null == privateKeyEntry) {
			/*
			 * Seems like this can happen for very old eID cards.
			 */
			throw new RuntimeException(
					"private key entry for alias not found: " + alias);
		}
		X509Certificate[] certificateChain = (X509Certificate[]) privateKeyEntry
				.getCertificateChain();
		this.signCertificateChain = new LinkedList<X509Certificate>();
		for (X509Certificate certificate : certificateChain) {
			this.signCertificateChain.add(certificate);
		}

		// TODO: why keep this also in close()?
		Security.removeProvider(this.pkcs11Provider.getName());
		this.pkcs11Provider = null;

		return signatureValue;
	}
}
