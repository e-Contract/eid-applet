/*
 * eID Applet Project.
 * Copyright (C) 2008-2012 FedICT.
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

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.Security;
import java.security.Signature;

import javax.swing.JOptionPane;

import org.junit.Test;

import sun.security.pkcs11.SunPKCS11;

public class PKCS11Test {

	@Test
	public void testTokenHasBeenRemovedError() throws Exception {
		File tmpConfigFile = File.createTempFile("pkcs11-", "conf");
		tmpConfigFile.deleteOnExit();
		PrintWriter configWriter = new PrintWriter(new FileOutputStream(
				tmpConfigFile), true);
		configWriter.println("name=SmartCard");
		configWriter.println("library=/usr/lib/libbeidpkcs11.so.0");
		configWriter.println("slotListIndex=1");

		SunPKCS11 provider = new SunPKCS11(tmpConfigFile.getAbsolutePath());
		Security.addProvider(provider);
		KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
		keyStore.load(null, null);
		{
			PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore
					.getEntry("Authentication", null);
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initSign(privateKeyEntry.getPrivateKey());
			byte[] toBeSigned = "hello world".getBytes();
			signature.update(toBeSigned);
			byte[] signatureValue = signature.sign();
		}
		JOptionPane.showMessageDialog(null,
				"Please remove and re-insert the token...");
		{
			PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore
					.getEntry("Authentication", null);
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initSign(privateKeyEntry.getPrivateKey());
			byte[] toBeSigned = "hello world".getBytes();
			signature.update(toBeSigned);
			byte[] signatureValue = signature.sign();
		}
	}

	@Test
	public void testTokenHasBeenRemovedWorkaround() throws Exception {
		File tmpConfigFile = File.createTempFile("pkcs11-", "conf");
		tmpConfigFile.deleteOnExit();
		PrintWriter configWriter = new PrintWriter(new FileOutputStream(
				tmpConfigFile), true);
		configWriter.println("name=SmartCard");
		configWriter.println("library=/usr/lib/libbeidpkcs11.so.0");
		configWriter.println("slotListIndex=1");

		SunPKCS11 provider = new SunPKCS11(tmpConfigFile.getAbsolutePath());
		Security.addProvider(provider);
		{
			KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
			keyStore.load(null, null);
			PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore
					.getEntry("Authentication", null);
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initSign(privateKeyEntry.getPrivateKey());
			byte[] toBeSigned = "hello world".getBytes();
			signature.update(toBeSigned);
			byte[] signatureValue = signature.sign();

		}
		JOptionPane.showMessageDialog(null,
				"Please remove and re-insert the token...");
		Security.removeProvider(provider.getName());
		{
			SunPKCS11 provider2 = new SunPKCS11(tmpConfigFile.getAbsolutePath());
			Security.addProvider(provider2);
			KeyStore keyStore = KeyStore.getInstance("PKCS11", provider2);
			keyStore.load(null, null);
			PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore
					.getEntry("Authentication", null);
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initSign(privateKeyEntry.getPrivateKey());
			byte[] toBeSigned = "hello world".getBytes();
			signature.update(toBeSigned);
			byte[] signatureValue = signature.sign();
			Security.removeProvider(provider2.getName());
		}
	}
}
