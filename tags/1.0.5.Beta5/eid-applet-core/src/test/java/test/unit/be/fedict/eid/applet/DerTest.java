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

package test.unit.be.fedict.eid.applet;

import java.security.MessageDigest;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

public class DerTest {

	private static final Log LOG = LogFactory.getLog(DerTest.class);

	@Test
	public void derSequence() throws Exception {
		DERSequence derSequence = new DERSequence();
		byte[] encodedDerSequence = derSequence.getEncoded();
		LOG.debug("DER sequence size: " + encodedDerSequence.length);
		LOG.debug("DER sequence: "
				+ new String(Hex.encodeHex(encodedDerSequence)));
		LOG.debug("ASN.1 DER sequence: " + ASN1Dump.dumpAsString(derSequence));

		DERInteger derInteger = new DERInteger(1234);
		byte[] encodedDerInteger = derInteger.getDEREncoded();
		LOG.debug("DER integer: "
				+ new String(Hex.encodeHex(encodedDerInteger)));
	}

	@Test
	public void digestInfo() throws Exception {
		byte[] message = "hello world".getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		byte[] digest = messageDigest.digest(message);
		LOG.debug("Digest: " + new String(Hex.encodeHex(digest)));
		DERObjectIdentifier hashAlgoId = OIWObjectIdentifiers.idSHA1;
		DigestInfo digestInfo = new DigestInfo(new AlgorithmIdentifier(
				hashAlgoId), digest);
		byte[] encodedDigestInfo = digestInfo.getEncoded();
		LOG.debug("Digest Info: "
				+ new String(Hex.encodeHex(encodedDigestInfo)));
	}

	@Test
	public void digestInfoPlainText() throws Exception {
		{
			byte[] message = "hello world".getBytes();
			LOG.debug("message: " + new String(Hex.encodeHex(message)));
			DERObjectIdentifier hashAlgoId = new DERObjectIdentifier(
					"2.16.56.1.2.1.3.1");
			DigestInfo digestInfo = new DigestInfo(new AlgorithmIdentifier(
					hashAlgoId), message);
			byte[] encodedDigestInfo = digestInfo.getEncoded();
			LOG.debug("Digest Info: "
					+ new String(Hex.encodeHex(encodedDigestInfo)));
		}
		{
			byte[] message = "Hello world 2".getBytes();
			LOG.debug("message: " + new String(Hex.encodeHex(message)));
			DERObjectIdentifier hashAlgoId = new DERObjectIdentifier(
					"2.16.56.1.2.1.3.1");
			DigestInfo digestInfo = new DigestInfo(new AlgorithmIdentifier(
					hashAlgoId), message);
			byte[] encodedDigestInfo = digestInfo.getEncoded();
			LOG.debug("Digest Info: "
					+ new String(Hex.encodeHex(encodedDigestInfo)));
		}

	}

	@Test
	public void digestInfoSha256() throws Exception {
		byte[] message = "hello world".getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		byte[] digest = messageDigest.digest(message);
		LOG.debug("Digest: " + new String(Hex.encodeHex(digest)));
		DERObjectIdentifier hashAlgoId = NISTObjectIdentifiers.id_sha256;
		DigestInfo digestInfo = new DigestInfo(new AlgorithmIdentifier(
				hashAlgoId), digest);
		byte[] encodedDigestInfo = digestInfo.getEncoded();
		LOG.debug("Digest Info: "
				+ new String(Hex.encodeHex(encodedDigestInfo)));
	}

	@Test
	public void digestInfoSha384() throws Exception {
		byte[] message = "hello world".getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-384");
		byte[] digest = messageDigest.digest(message);
		LOG.debug("Digest: " + new String(Hex.encodeHex(digest)));
		DERObjectIdentifier hashAlgoId = NISTObjectIdentifiers.id_sha384;
		DigestInfo digestInfo = new DigestInfo(new AlgorithmIdentifier(
				hashAlgoId), digest);
		byte[] encodedDigestInfo = digestInfo.getEncoded();
		LOG.debug("Digest Info: "
				+ new String(Hex.encodeHex(encodedDigestInfo)));
	}

	@Test
	public void digestInfoSha512() throws Exception {
		byte[] message = "hello world".getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
		byte[] digest = messageDigest.digest(message);
		LOG.debug("Digest: " + new String(Hex.encodeHex(digest)));
		DERObjectIdentifier hashAlgoId = NISTObjectIdentifiers.id_sha512;
		DigestInfo digestInfo = new DigestInfo(new AlgorithmIdentifier(
				hashAlgoId), digest);
		byte[] encodedDigestInfo = digestInfo.getEncoded();
		LOG.debug("Digest Info: "
				+ new String(Hex.encodeHex(encodedDigestInfo)));
	}

	@Test
	public void digestInfoSha224() throws Exception {
		byte[] message = "hello world".getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-224",
				new BouncyCastleProvider());
		byte[] digest = messageDigest.digest(message);
		LOG.debug("Digest: " + new String(Hex.encodeHex(digest)));
		DERObjectIdentifier hashAlgoId = NISTObjectIdentifiers.id_sha224;
		DigestInfo digestInfo = new DigestInfo(new AlgorithmIdentifier(
				hashAlgoId), digest);
		byte[] encodedDigestInfo = digestInfo.getEncoded();
		LOG.debug("Digest Info: "
				+ new String(Hex.encodeHex(encodedDigestInfo)));
	}

	@Test
	public void digestInfoRipemd160() throws Exception {
		byte[] message = "hello world".getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("RIPEMD160",
				new BouncyCastleProvider());
		byte[] digest = messageDigest.digest(message);
		LOG.debug("Digest: " + new String(Hex.encodeHex(digest)));
		DERObjectIdentifier hashAlgoId = X509ObjectIdentifiers.ripemd160;
		DigestInfo digestInfo = new DigestInfo(new AlgorithmIdentifier(
				hashAlgoId), digest);
		byte[] encodedDigestInfo = digestInfo.getEncoded();
		LOG.debug("Digest Info: "
				+ new String(Hex.encodeHex(encodedDigestInfo)));
	}

	@Test
	public void digestInfoRipemd128() throws Exception {
		byte[] message = "hello world".getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("RIPEMD128",
				new BouncyCastleProvider());
		byte[] digest = messageDigest.digest(message);
		LOG.debug("Digest: " + new String(Hex.encodeHex(digest)));
		DERObjectIdentifier hashAlgoId = new DERObjectIdentifier("1.3.36.3.2.2");
		DigestInfo digestInfo = new DigestInfo(new AlgorithmIdentifier(
				hashAlgoId), digest);
		byte[] encodedDigestInfo = digestInfo.getEncoded();
		LOG.debug("Digest Info: "
				+ new String(Hex.encodeHex(encodedDigestInfo)));
	}

	@Test
	public void digestInfoRipemd256() throws Exception {
		byte[] message = "hello world".getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("RIPEMD256",
				new BouncyCastleProvider());
		byte[] digest = messageDigest.digest(message);
		LOG.debug("Digest: " + new String(Hex.encodeHex(digest)));
		DERObjectIdentifier hashAlgoId = new DERObjectIdentifier("1.3.36.3.2.3");
		DigestInfo digestInfo = new DigestInfo(new AlgorithmIdentifier(
				hashAlgoId), digest);
		byte[] encodedDigestInfo = digestInfo.getEncoded();
		LOG.debug("Digest Info: "
				+ new String(Hex.encodeHex(encodedDigestInfo)));
	}

	@Test
	public void bouncycastleHashAlgos() throws Exception {
		byte[] message = "hello world".getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("RIPEMD160",
				new BouncyCastleProvider());
		byte[] digest = messageDigest.digest(message);
		LOG.debug("RIPEMD160 size: " + digest.length);

		messageDigest = MessageDigest.getInstance("RIPEMD128",
				new BouncyCastleProvider());
		digest = messageDigest.digest(message);
		LOG.debug("RIPEMD128 size: " + digest.length);

		messageDigest = MessageDigest.getInstance("RIPEMD256",
				new BouncyCastleProvider());
		digest = messageDigest.digest(message);
		LOG.debug("RIPEMD256 size: " + digest.length);

		messageDigest = MessageDigest.getInstance("RIPEMD320",
				new BouncyCastleProvider());
		digest = messageDigest.digest(message);
		LOG.debug("RIPEMD320 size: " + digest.length);

		messageDigest = MessageDigest.getInstance("SHA-224",
				new BouncyCastleProvider());
		digest = messageDigest.digest(message);
		LOG.debug("SHA-224 size: " + digest.length);
	}
}
