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

package test.unit.be.fedict.eid.applet.service.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.OutputStream;
import java.net.URL;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import be.fedict.eid.applet.service.signer.TemporaryDataStorage;
import be.fedict.eid.applet.service.signer.ooxml.AbstractOOXMLSignatureService;
import be.fedict.eid.applet.service.spi.DigestInfo;

public class AbstractOOXMLSignatureServiceTest {

	private static final Log LOG = LogFactory
			.getLog(AbstractOOXMLSignatureServiceTest.class);

	private static class OOXMLTestSignatureService extends
			AbstractOOXMLSignatureService {

		private final URL ooxmlUrl;

		private final TemporaryTestDataStorage temporaryDataStorage;

		private final ByteArrayOutputStream signedOOXMLOutputStream;

		public OOXMLTestSignatureService(URL ooxmlUrl) {
			this.temporaryDataStorage = new TemporaryTestDataStorage();
			this.signedOOXMLOutputStream = new ByteArrayOutputStream();
			this.ooxmlUrl = ooxmlUrl;
		}

		@Override
		protected URL getOfficeOpenXMLDocumentURL() {
			return this.ooxmlUrl;
		}

		@Override
		protected OutputStream getSignedOfficeOpenXMLDocumentOutputStream() {
			return this.signedOOXMLOutputStream;
		}

		@Override
		protected TemporaryDataStorage getTemporaryDataStorage() {
			return this.temporaryDataStorage;
		}
	}

	@Test
	public void testPreSign() throws Exception {
		// setup
		URL ooxmlUrl = AbstractOOXMLSignatureServiceTest.class
				.getResource("/hello-world-unsigned.docx");
		assertNotNull(ooxmlUrl);

		OOXMLTestSignatureService signatureService = new OOXMLTestSignatureService(
				ooxmlUrl);

		// operate
		DigestInfo digestInfo = signatureService.preSign(null, null);

		// verify
		assertNotNull(digestInfo);
		LOG.debug("digest algo: " + digestInfo.digestAlgo);
		LOG.debug("digest description: " + digestInfo.description);
		assertEquals("Office OpenXML Document", digestInfo.description);
		assertNotNull(digestInfo.digestAlgo);
		assertNotNull(digestInfo.digestValue);

		TemporaryDataStorage temporaryDataStorage = signatureService
				.getTemporaryDataStorage();
		String preSignResult = IOUtils.toString(temporaryDataStorage
				.getTempInputStream());
		LOG.debug("pre-sign result: " + preSignResult);
		File tmpFile = File.createTempFile("ooxml-pre-sign-", ".xml");
		FileUtils.writeStringToFile(tmpFile, preSignResult);
		LOG.debug("tmp pre-sign file: " + tmpFile.getAbsolutePath());
	}
}
