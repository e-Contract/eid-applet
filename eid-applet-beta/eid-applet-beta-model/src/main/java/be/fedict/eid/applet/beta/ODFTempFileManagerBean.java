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

package be.fedict.eid.applet.beta;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;

import javax.ejb.Stateless;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

@Stateless
public class ODFTempFileManagerBean implements ODFTempFileManager {

	private static final Log LOG = LogFactory
			.getLog(ODFTempFileManagerBean.class);

	public void cleanup() {
		LOG.debug("cleanup");
		HttpSession httpSession = getHttpSession();
		URL odfUrl = (URL) httpSession.getAttribute(ODF_URL_SESSION_ATTRIBUTE);
		if (null == odfUrl) {
			return;
		}
		File odfFile;
		try {
			odfFile = new File(odfUrl.toURI());
		} catch (URISyntaxException e) {
			throw new RuntimeException("URI error: " + e.getMessage(), e);
		}
		if (false == odfFile.exists()) {
			LOG.warn("tmp ODF file does not exist: "
					+ odfFile.getAbsolutePath());
		}
		LOG.debug("deleting tmp file: " + odfFile.getAbsolutePath());
		boolean result = odfFile.delete();
		if (false == result) {
			LOG.warn("could not delete temp ODF file: "
					+ odfFile.getAbsolutePath());
		}
		httpSession.removeAttribute(ODF_URL_SESSION_ATTRIBUTE);
	}

	public URL createTempFile() throws IOException {
		LOG.debug("create temp file");
		cleanup();
		File tmpFile = File.createTempFile("eid-beta-", ".odf");
		URL tmpFileUrl = tmpFile.toURI().toURL();
		HttpSession httpSession = getHttpSession();
		httpSession.setAttribute(ODF_URL_SESSION_ATTRIBUTE, tmpFileUrl);
		LOG.debug("tmp file: " + tmpFileUrl);
		return tmpFileUrl;
	}

	private HttpSession getHttpSession() {
		HttpServletRequest httpServletRequest;
		try {
			httpServletRequest = (HttpServletRequest) PolicyContext
					.getContext("javax.servlet.http.HttpServletRequest");
		} catch (PolicyContextException e) {
			throw new RuntimeException("JACC error: " + e.getMessage());
		}

		HttpSession httpSession = httpServletRequest.getSession();
		return httpSession;
	}

	public URL getTempFile() {
		LOG.debug("get temp file");
		HttpSession httpSession = getHttpSession();
		URL tmpFileUrl = (URL) httpSession
				.getAttribute(ODF_URL_SESSION_ATTRIBUTE);
		if (null == tmpFileUrl) {
			throw new RuntimeException("no temp file available");
		}
		return tmpFileUrl;
	}
}
