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

package be.fedict.eid.applet.service.impl.handler;

import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import be.fedict.eid.applet.service.impl.MessageHandler;
import be.fedict.eid.applet.service.impl.ServiceLocator;
import be.fedict.eid.applet.service.spi.DigestInfo;
import be.fedict.eid.applet.service.spi.SignatureService;
import be.fedict.eid.applet.shared.FileDigestsDataMessage;
import be.fedict.eid.applet.shared.SignRequestMessage;

/**
 * Message handler for file digests data messages.
 * 
 * @author fcorneli
 * 
 */
public class FileDigestsDataMessageHandler implements
		MessageHandler<FileDigestsDataMessage> {

	private ServiceLocator<SignatureService> signatureServiceLocator;

	private boolean removeCard;

	private boolean logoff;

	public Object handleMessage(FileDigestsDataMessage message,
			Map<String, String> httpHeaders, HttpServletRequest request,
			HttpSession session) throws ServletException {
		List<DigestInfo> fileDigestInfos = new LinkedList<DigestInfo>();

		List<String> messageFileDigestInfos = message.fileDigestInfos;
		Iterator<String> messageIterator = messageFileDigestInfos.iterator();
		while (messageIterator.hasNext()) {
			String digestAlgo = messageIterator.next();
			String hexDigestValue = messageIterator.next();
			String description = messageIterator.next();
			byte[] digestValue;
			try {
				digestValue = Hex.decodeHex(hexDigestValue.toCharArray());
			} catch (DecoderException e) {
				throw new ServletException("digest value decode error: "
						+ e.getMessage(), e);
			}
			fileDigestInfos.add(new DigestInfo(digestValue, digestAlgo,
					description));
		}

		// TODO DRY refactor: is a copy-paste from HelloMessageHandler
		SignatureService signatureService = this.signatureServiceLocator
				.locateService();

		DigestInfo digestInfo;
		try {
			digestInfo = signatureService.preSign(fileDigestInfos, null);
		} catch (NoSuchAlgorithmException e) {
			throw new ServletException("no such algo: " + e.getMessage(), e);
		}

		// also save it in the session for later verification
		SignatureDataMessageHandler.setDigestValue(digestInfo.digestValue, session);

		SignRequestMessage signRequestMessage = new SignRequestMessage(
				digestInfo.digestValue, digestInfo.digestAlgo,
				digestInfo.description, this.logoff, this.removeCard);
		return signRequestMessage;
	}

	public void init(ServletConfig config) throws ServletException {
		this.signatureServiceLocator = new ServiceLocator<SignatureService>(
				HelloMessageHandler.SIGNATURE_SERVICE_INIT_PARAM_NAME, config);

		String removeCard = config
				.getInitParameter(HelloMessageHandler.REMOVE_CARD_INIT_PARAM_NAME);
		if (null != removeCard) {
			this.removeCard = Boolean.parseBoolean(removeCard);
		}

		String logoff = config
				.getInitParameter(HelloMessageHandler.LOGOFF_INIT_PARAM_NAME);
		if (null != logoff) {
			this.logoff = Boolean.parseBoolean(logoff);
		}
	}
}
