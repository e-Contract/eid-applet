/*
 * eID Applet Project.
 * Copyright (C) 2015 e-Contract.be BVBA.
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

import be.fedict.eid.applet.View;

/**
 * Simple wrapper around view to limit the changes to LibJ2PCSCGNULinuxFix.
 * 
 * @author Frank Cornelis
 *
 */
public class Logger {

	private final View view;

	public Logger(View view) {
		this.view = view;
	}

	public void debug(String message) {
		this.view.addDetailMessage(message);
	}
}
