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

package test.be.fedict.eid.applet;

import java.awt.Component;
import java.util.Locale;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.DiagnosticTests;
import be.fedict.eid.applet.Messages;
import be.fedict.eid.applet.Status;
import be.fedict.eid.applet.View;

public class TestView implements View {

	private static final Log LOG = LogFactory.getLog(TestView.class);

	private Messages messages = new Messages(Locale.getDefault());

	@Override
	public void addDetailMessage(String detailMessage) {
		LOG.debug("detail: " + detailMessage);
	}

	@Override
	public Component getParentComponent() {
		return null;
	}

	@Override
	public boolean privacyQuestion(boolean includeAddress,
			boolean includePhoto, String identityDataUsage) {
		return false;
	}

	@Override
	public void setStatusMessage(Status status, Messages.MESSAGE_ID messageId) {
		String statusMessage = this.messages.getMessage(messageId);
		LOG.debug("status message: " + status + ": " + statusMessage);
		if (Status.ERROR == status) {
			throw new RuntimeException("status ERROR received");
		}
	}

	@Override
	public void addTestResult(DiagnosticTests diagnosticTest, boolean success,
			String description) {
	}

	@Override
	public void setProgressIndeterminate() {
	}

	@Override
	public void resetProgress(int max) {
	}

	@Override
	public void increaseProgress() {
	}
}