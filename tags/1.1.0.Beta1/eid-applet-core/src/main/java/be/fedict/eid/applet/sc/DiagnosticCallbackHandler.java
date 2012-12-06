/*
 * eID Applet Project.
 * Copyright (C) 2010 FedICT.
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

import be.fedict.eid.applet.DiagnosticTests;

/**
 * Callback handler for diagnostic tests.
 * 
 * @author Frank Cornelis
 * 
 */
public interface DiagnosticCallbackHandler {

	/**
	 * Adds a test result from the running diagnostics.
	 * 
	 * @param test
	 *            the performed test.
	 * @param success
	 *            the result of the performed test. <code>true</code> is OK,
	 *            <code>false</code> otherwise.
	 * @param information
	 *            additional optional information about the performed test.
	 */
	void addTestResult(DiagnosticTests test, boolean success, String information);
}
