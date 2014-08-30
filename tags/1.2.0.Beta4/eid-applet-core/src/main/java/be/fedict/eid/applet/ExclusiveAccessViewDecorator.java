/*
 * eID Applet Project.
 * Copyright (C) 2014 e-Contract.be BVBA.
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

package be.fedict.eid.applet;

import java.awt.Component;

import javax.smartcardio.CardException;
import javax.swing.JOptionPane;

import be.fedict.eid.applet.Messages.MESSAGE_ID;
import be.fedict.eid.applet.sc.PcscEid;

/**
 * View decorator that manages the exclusive card lock work-around for Windows
 * 8.
 * 
 * @author Frank Cornelis
 *
 */
public class ExclusiveAccessViewDecorator implements View {

	private final View delegate;

	private final PcscEid pcscEid;

	public ExclusiveAccessViewDecorator(View delegate, PcscEid pcscEid) {
		this.delegate = delegate;
		this.pcscEid = pcscEid;
	}

	@Override
	public void addDetailMessage(String detailMessage) {
		this.delegate.addDetailMessage(detailMessage);
	}

	@Override
	public void setStatusMessage(Status status, MESSAGE_ID messageId) {
		this.delegate.setStatusMessage(status, messageId);
	}

	@Override
	public boolean privacyQuestion(boolean includeAddress,
			boolean includePhoto, String identityDataUsage) {
		try {
			this.pcscEid.endExclusive();
		} catch (CardException e) {
			this.delegate
					.addDetailMessage("could not end exclusive card access");
			return false;
		}
		try {
			return this.delegate.privacyQuestion(includeAddress, includePhoto,
					identityDataUsage);
		} finally {
			try {
				this.pcscEid.beginExclusive();
			} catch (CardException e) {
				this.delegate
						.addDetailMessage("could not acquire exclusive card access");
				return false;
			}
		}
	}

	@Override
	public Component getParentComponent() {
		return this.delegate.getParentComponent();
	}

	@Override
	public void setProgressIndeterminate() {
		this.delegate.setProgressIndeterminate();
	}

	@Override
	public void resetProgress(int max) {
		this.delegate.resetProgress(max);
	}

	@Override
	public void increaseProgress() {
		this.delegate.increaseProgress();
	}

	@Override
	public void confirmAuthenticationSignature(String message) {
		try {
			this.pcscEid.endExclusive();
		} catch (CardException e) {
			throw new SecurityException("could not end exclusive card access");
		}
		try {
			this.delegate.confirmAuthenticationSignature(message);
		} finally {
			try {
				this.pcscEid.beginExclusive();
			} catch (CardException e) {
				throw new SecurityException(
						"could not acquire exclusive card access");
			}
		}
	}

	@Override
	public int confirmSigning(String description, String digestAlgo) {
		try {
			this.pcscEid.endExclusive();
		} catch (CardException e) {
			this.delegate
					.addDetailMessage("could not end exclusive card access");
			return JOptionPane.CANCEL_OPTION;
		}
		try {
			return this.delegate.confirmSigning(description, digestAlgo);
		} finally {
			try {
				this.pcscEid.beginExclusive();
			} catch (CardException e) {
				this.delegate
						.addDetailMessage("could not acquire exclusive card access");
				return JOptionPane.CANCEL_OPTION;
			}
		}
	}
}
