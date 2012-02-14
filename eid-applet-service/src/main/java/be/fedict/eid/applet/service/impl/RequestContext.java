/*
 * eID Applet Project.
 * Copyright (C) 2008-2010 FedICT.
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

package be.fedict.eid.applet.service.impl;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.shared.protocol.ProtocolState;
import be.fedict.eid.applet.shared.protocol.ProtocolStateListener;

/**
 * Keeps track of what was requested from the client. Manages its own life-cycle
 * within the scope of a protocol run.
 * 
 * @author Frank Cornelis
 * 
 */
public class RequestContext implements ProtocolStateListener {

	private static final Log LOG = LogFactory.getLog(RequestContext.class);

	private final HttpSession httpSession;

	public final static String INCLUDE_IDENTITY_SESSION_ATTRIBUTE = RequestContext.class
			.getName() + ".IncludeIdentity";

	public final static String INCLUDE_ADDRESS_SESSION_ATTRIBUTE = RequestContext.class
			.getName() + ".IncludeAddress";

	public final static String INCLUDE_PHOTO_SESSION_ATTRIBUTE = RequestContext.class
			.getName() + ".IncludePhoto";

	public final static String INCLUDE_CERTIFICATES_SESSION_ATTRIBUTE = RequestContext.class
			.getName() + ".IncludeCertificates";

	public static final String TRANSACTION_MESSAGE_SESSION_ATTRIBUTE = RequestContext.class
			.getName() + ".TransactionMessage";

	public RequestContext(HttpServletRequest request) {
		this(request.getSession());
	}

	public RequestContext(HttpSession httpSession) {
		this.httpSession = httpSession;
	}

	public void protocolStateTransition(ProtocolState newProtocolState) {
	}

	public void startProtocolRun() {
		clearRequestContext();
	}

	public void stopProtocolRun() {
		clearRequestContext();
	}

	private void clearRequestContext() {
		LOG.debug("clearing request context");
		this.httpSession.removeAttribute(INCLUDE_IDENTITY_SESSION_ATTRIBUTE);
		this.httpSession.removeAttribute(INCLUDE_ADDRESS_SESSION_ATTRIBUTE);
		this.httpSession.removeAttribute(INCLUDE_PHOTO_SESSION_ATTRIBUTE);
		this.httpSession
				.removeAttribute(INCLUDE_CERTIFICATES_SESSION_ATTRIBUTE);
		this.httpSession.removeAttribute(TRANSACTION_MESSAGE_SESSION_ATTRIBUTE);
	}

	public void setIncludeIdentity(boolean includeIdentity) {
		this.httpSession.setAttribute(INCLUDE_IDENTITY_SESSION_ATTRIBUTE,
				includeIdentity);
	}

	public void setIncludeAddress(boolean includeAddress) {
		this.httpSession.setAttribute(INCLUDE_ADDRESS_SESSION_ATTRIBUTE,
				includeAddress);
	}

	public void setIncludePhoto(boolean includePhoto) {
		this.httpSession.setAttribute(INCLUDE_PHOTO_SESSION_ATTRIBUTE,
				includePhoto);
	}

	public void setIncludeCertificates(boolean includeCertificates) {
		this.httpSession.setAttribute(INCLUDE_CERTIFICATES_SESSION_ATTRIBUTE,
				includeCertificates);
	}

	public void setTransactionMessage(String transactionMessage) {
		this.httpSession.setAttribute(TRANSACTION_MESSAGE_SESSION_ATTRIBUTE,
				transactionMessage);
	}

	public boolean includeIdentity() {
		return getBoolean(INCLUDE_IDENTITY_SESSION_ATTRIBUTE);
	}

	public boolean includeAddress() {
		return getBoolean(INCLUDE_ADDRESS_SESSION_ATTRIBUTE);
	}

	public boolean includePhoto() {
		return getBoolean(INCLUDE_PHOTO_SESSION_ATTRIBUTE);
	}

	public boolean includeCertificates() {
		return getBoolean(INCLUDE_CERTIFICATES_SESSION_ATTRIBUTE);
	}

	private boolean getBoolean(String attributeName) {
		Object attributeValue = this.httpSession.getAttribute(attributeName);
		if (null == attributeValue) {
			return false;
		}
		return (Boolean) attributeValue;
	}

	public String getTransactionMessage() {
		String transactionMessage = (String) this.httpSession
				.getAttribute(TRANSACTION_MESSAGE_SESSION_ATTRIBUTE);
		return transactionMessage;
	}
}
