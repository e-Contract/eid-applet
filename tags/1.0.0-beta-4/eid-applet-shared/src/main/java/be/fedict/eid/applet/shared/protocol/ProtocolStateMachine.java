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

package be.fedict.eid.applet.shared.protocol;

import java.util.LinkedList;
import java.util.List;

import be.fedict.eid.applet.shared.annotation.ProtocolStateAllowed;
import be.fedict.eid.applet.shared.annotation.StartRequestMessage;
import be.fedict.eid.applet.shared.annotation.StateTransition;
import be.fedict.eid.applet.shared.annotation.StopResponseMessage;

/**
 * Protocol State Machine.
 * 
 * @author Frank Cornelis
 * 
 */
public class ProtocolStateMachine {

	private final ProtocolContext protocolContext;

	private final List<ProtocolStateListener> protocolStateListeners;

	/**
	 * Main constructor.
	 * 
	 * @param protocolContext
	 */
	public ProtocolStateMachine(ProtocolContext protocolContext) {
		this.protocolContext = protocolContext;
		this.protocolStateListeners = new LinkedList<ProtocolStateListener>();
	}

	/**
	 * Adds a protocol state listener.
	 * 
	 * @param protocolStateListener
	 */
	public void addProtocolStateListener(
			ProtocolStateListener protocolStateListener) {
		this.protocolStateListeners.add(protocolStateListener);
	}

	/**
	 * Checks the given response message against the protocol state rules.
	 * 
	 * @param responseMessage
	 * @throws ServletException
	 */
	public void checkResponseMessage(Object responseMessage) {
		ProtocolState protocolState = this.protocolContext.getProtocolState();
		if (null == protocolState) {
			throw new RuntimeException("responding without a protocol state");
		}
		Class<?> responseMessageClass = responseMessage.getClass();
		StopResponseMessage stopResponseMessageAnnotation = responseMessageClass
				.getAnnotation(StopResponseMessage.class);
		if (null != stopResponseMessageAnnotation) {
			this.protocolContext.removeProtocolState();
		}
		StateTransition stateTransitionAnnotation = responseMessageClass
				.getAnnotation(StateTransition.class);
		if (null != stateTransitionAnnotation) {
			ProtocolState newProtocolState = stateTransitionAnnotation.value();
			this.protocolContext.setProtocolState(newProtocolState);
			notifyProtocolListeners(newProtocolState);
		}
	}

	private void notifyProtocolListeners(ProtocolState newProtocolState) {
		for (ProtocolStateListener protocolStateListener : this.protocolStateListeners) {
			protocolStateListener.protocolStateTransition(newProtocolState);
		}
	}

	/**
	 * Checks the given request message against protocol state rules.
	 * 
	 * @param requestMessage
	 * @throws ServletException
	 */
	public void checkRequestMessage(Object requestMessage) {
		// TODO return some non-runtime exception
		ProtocolState protocolState = this.protocolContext.getProtocolState();
		Class<?> requestMessageClass = requestMessage.getClass();
		StartRequestMessage startRequestMessageAnnotation = requestMessageClass
				.getAnnotation(StartRequestMessage.class);
		if (null == startRequestMessageAnnotation) {
			if (null == protocolState) {
				throw new RuntimeException("expected a protocol start message");
			}
			ProtocolStateAllowed protocolStateAllowedAnnotation = requestMessageClass
					.getAnnotation(ProtocolStateAllowed.class);
			if (null == protocolStateAllowedAnnotation) {
				throw new RuntimeException(
						"cannot check protocol state for message: "
								+ requestMessageClass.getSimpleName());
			}
			ProtocolState allowedProtocolState = protocolStateAllowedAnnotation
					.value();
			if (protocolState != allowedProtocolState) {
				throw new RuntimeException(
						"protocol state incorrect. expected: "
								+ allowedProtocolState + "; actual: "
								+ protocolState);
			}
		} else {
			if (null != protocolState) {
				/*
				 * Throwing an exception here might be to strict since we want
				 * to allow easy recovery from a crashed eID Applet. I.e. no
				 * need to restart the web browser.
				 */
			}
			ProtocolState initialState = startRequestMessageAnnotation.value();
			this.protocolContext.setProtocolState(initialState);
			notifyProtocolListeners(initialState);
		}
	}
}
