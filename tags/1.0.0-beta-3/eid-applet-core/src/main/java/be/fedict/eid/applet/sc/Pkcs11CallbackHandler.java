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

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import be.fedict.eid.applet.Dialogs;
import be.fedict.eid.applet.Messages;
import be.fedict.eid.applet.View;

/**
 * Callback handler implementation for PKCS#11 keystore.
 * 
 * @author fcorneli
 * 
 */
public class Pkcs11CallbackHandler implements CallbackHandler {

	private final View view;

	private final Dialogs dialogs;

	/**
	 * Main constructor.
	 * 
	 * @param view
	 * @param messages
	 */
	public Pkcs11CallbackHandler(View view, Messages messages) {
		this.view = view;
		this.dialogs = new Dialogs(this.view, messages);
	}

	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
		this.view.addDetailMessage("PKCS#11 callback");
		for (Callback callback : callbacks) {
			if (callback instanceof PasswordCallback) {
				PasswordCallback passwordCallback = (PasswordCallback) callback;
				this.view.addDetailMessage("password callback prompt: "
						+ passwordCallback.getPrompt());
				char[] pin = this.dialogs.getPin();
				passwordCallback.setPassword(pin);
			}
		}
	}
}
