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
import java.io.Serializable;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.LinkedList;
import java.util.List;

import javax.ejb.Stateless;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

@Stateless
public class TempFileManagerBean implements TempFileManager {

	private static final String TMP_FILE_URLS_SESSION_ATTRIBUTE = TempFileManagerBean.class
			.getName()
			+ ".tmpFileUrls";

	private static final Log LOG = LogFactory.getLog(TempFileManagerBean.class);

	private static class TmpSessionFile implements Serializable {

		private static final long serialVersionUID = 1L;

		private String sessionAttribute;

		private URL tmpFileUrl;

		public TmpSessionFile() {
			super();
		}

		public TmpSessionFile(String sessionAttribute, URL tmpFileUrl) {
			this.sessionAttribute = sessionAttribute;
			this.tmpFileUrl = tmpFileUrl;
		}
	}

	private List<TmpSessionFile> getTmpSessionFiles(HttpSession httpSession) {
		List<TmpSessionFile> tmpFileUrls = (List<TmpSessionFile>) httpSession
				.getAttribute(TMP_FILE_URLS_SESSION_ATTRIBUTE);
		if (null == tmpFileUrls) {
			tmpFileUrls = new LinkedList<TmpSessionFile>();
			httpSession.setAttribute(TMP_FILE_URLS_SESSION_ATTRIBUTE,
					tmpFileUrls);
		}
		return tmpFileUrls;
	}

	public void cleanup(HttpSession httpSession) {
		LOG.debug("cleanup");
		List<TmpSessionFile> tmpSessionFiles = getTmpSessionFiles(httpSession);
		for (TmpSessionFile tmpSessionFile : tmpSessionFiles) {
			cleanup(tmpSessionFile, httpSession);
		}
	}

	private void cleanup(TmpSessionFile tmpSessionFile, HttpSession httpSession) {
		LOG.debug("removing session attribute: "
				+ tmpSessionFile.sessionAttribute);
		httpSession.removeAttribute(tmpSessionFile.sessionAttribute);

		File file;
		try {
			file = new File(tmpSessionFile.tmpFileUrl.toURI());
		} catch (URISyntaxException e) {
			throw new RuntimeException("URI error: " + e.getMessage(), e);
		}
		if (false == file.exists()) {
			LOG.warn("tmp file does not exist: " + file.getAbsolutePath());
			return;
		}
		LOG.debug("deleting tmp file: " + file.getAbsolutePath());
		boolean result = file.delete();
		if (false == result) {
			LOG.warn("could not delete temp file: " + file.getAbsolutePath());
		}
	}

	private void cleanup(String sessionAttribute) {
		HttpSession httpSession = getHttpSession();
		URL tmpFileUrl = (URL) httpSession.getAttribute(sessionAttribute);

		LOG.debug("removing session attribute: " + sessionAttribute);
		httpSession.removeAttribute(sessionAttribute);

		if (null == tmpFileUrl) {
			return;
		}
		File file;
		try {
			file = new File(tmpFileUrl.toURI());
		} catch (URISyntaxException e) {
			throw new RuntimeException("URI error: " + e.getMessage(), e);
		}
		if (false == file.exists()) {
			LOG.debug("tmp file does not exist: " + file.getAbsolutePath());
			return;
		}
		LOG.debug("deleting tmp file: " + file.getAbsolutePath());
		boolean result = file.delete();
		if (false == result) {
			LOG.debug("could not delete temp file: " + file.getAbsolutePath());
		}
	}

	public URL createTempFile(String sessionAttribute) throws IOException {
		LOG.debug("create temp file: " + sessionAttribute);
		cleanup(sessionAttribute);
		File tmpFile = File.createTempFile("eid-beta-", ".tmp");
		URL tmpFileUrl = tmpFile.toURI().toURL();
		HttpSession httpSession = getHttpSession();
		httpSession.setAttribute(sessionAttribute, tmpFileUrl);
		LOG.debug("tmp file: " + tmpFileUrl);

		/*
		 * Add to the list of tmp session files so we can have a cleanup when
		 * the HTTP session is being destroyed.
		 */
		List<TmpSessionFile> tmpSessionFiles = getTmpSessionFiles(httpSession);
		TmpSessionFile tmpSessionFile = new TmpSessionFile(sessionAttribute,
				tmpFileUrl);
		tmpSessionFiles.add(tmpSessionFile);

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

	public URL getTempFile(String sessionAttribute) {
		LOG.debug("get temp file: " + sessionAttribute);
		HttpSession httpSession = getHttpSession();
		URL tmpFileUrl = (URL) httpSession.getAttribute(sessionAttribute);
		if (null == tmpFileUrl) {
			throw new RuntimeException("no temp file available: "
					+ sessionAttribute);
		}
		return tmpFileUrl;
	}
}
