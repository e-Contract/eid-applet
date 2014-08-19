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

package be.fedict.eid.applet.service.cdi;

public class StartEvent {

	private IdentificationRequest identificationRequest;

	private AuthenticationRequest authenticationRequest;

	public IdentificationRequest performIdentification() {
		this.identificationRequest = new IdentificationRequest();
		return this.identificationRequest;
	}

	public IdentificationRequest getIdentificationRequest() {
		return this.identificationRequest;
	}

	public AuthenticationRequest performAuthentication() {
		this.authenticationRequest = new AuthenticationRequest();
		return this.authenticationRequest;
	}

	public AuthenticationRequest getAuthenticationRequest() {
		return this.authenticationRequest;
	}

	public class AuthenticationRequest {

		private boolean logoff;

		private boolean removeCard;

		private boolean preLogoff;

		private boolean includeAddress;

		private boolean includeIdentity;

		private boolean includePhoto;

		private boolean requireSecureReader;

		private String transactionMessage;

		public AuthenticationRequest logoff() {
			this.logoff = true;
			return this;
		}

		public AuthenticationRequest removeCard() {
			this.removeCard = true;
			return this;
		}

		public AuthenticationRequest preLogoff() {
			this.preLogoff = true;
			return this;
		}

		public AuthenticationRequest includeAddress() {
			this.includeAddress = true;
			return this;
		}

		public AuthenticationRequest includeIdentity() {
			this.includeIdentity = true;
			return this;
		}

		public AuthenticationRequest includePhoto() {
			this.includePhoto = true;
			return this;
		}

		public AuthenticationRequest requireSecureReader() {
			this.requireSecureReader = true;
			return this;
		}

		public AuthenticationRequest setTransactionMessage(
				String transactionMessage) {
			this.transactionMessage = transactionMessage;
			return this;
		}

		public boolean isLogoff() {
			return this.logoff;
		}

		public boolean isRemoveCard() {
			return this.removeCard;
		}

		public boolean isPreLogoff() {
			return this.preLogoff;
		}

		public boolean isIncludeAddress() {
			return this.includeAddress;
		}

		public boolean isIncludeIdentity() {
			return this.includeIdentity;
		}

		public boolean isIncludePhoto() {
			return this.includePhoto;
		}

		public boolean isRequireSecureReader() {
			return this.requireSecureReader;
		}

		public String getTransactionMessage() {
			return this.transactionMessage;
		}
	}

	public class IdentificationRequest {

		private boolean includeAddress;

		private boolean includePhoto;

		private boolean includeCertificates;

		private boolean removeCard;

		private String identityDataUsage;

		public IdentificationRequest includeAddress() {
			this.includeAddress = true;
			return this;
		}

		public IdentificationRequest includePhoto() {
			this.includePhoto = true;
			return this;
		}

		public IdentificationRequest includeCertificates() {
			this.includeCertificates = true;
			return this;
		}

		public IdentificationRequest removeCard() {
			this.removeCard = true;
			return this;
		}

		public boolean isIncludeAddress() {
			return this.includeAddress;
		}

		public boolean isIncludePhoto() {
			return this.includePhoto;
		}

		public boolean isIncludeCertificates() {
			return this.includeCertificates;
		}

		public boolean isRemoveCard() {
			return this.removeCard;
		}

		public IdentificationRequest setIdentityDataUsage(
				String identityDataUsage) {
			this.identityDataUsage = identityDataUsage;
			return this;
		}

		public String getIdentityDataUsage() {
			return this.identityDataUsage;
		}
	}
}
