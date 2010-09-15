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

import java.security.KeyStore.CallbackHandlerProtection;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.ProtectionParameter;

import javax.security.auth.callback.CallbackHandler;

import be.fedict.eid.applet.Messages;
import be.fedict.eid.applet.View;

/**
 * Keystore load/store parameter implementation for the PKCS#11 keystore.
 * 
 * @author Frank Cornelis
 * 
 */
public class Pkcs11LoadStoreParameter implements LoadStoreParameter {

	private final View view;

	private final CallbackHandlerProtection callbackHandlerProtection;

	public Pkcs11LoadStoreParameter(View view, Messages messages) {
		this.view = view;
		CallbackHandler callbackHandler = new Pkcs11CallbackHandler(this.view,
				messages);
		this.callbackHandlerProtection = new CallbackHandlerProtection(
				callbackHandler);
	}

	public ProtectionParameter getProtectionParameter() {
		this.view.addDetailMessage("getting protection parameter");
		return this.callbackHandlerProtection;
	}
}
