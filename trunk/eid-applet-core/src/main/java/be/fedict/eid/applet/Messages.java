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

package be.fedict.eid.applet;

import java.util.Locale;
import java.util.ResourceBundle;

/**
 * Util class to manage the i18n messages used within the eID Applet UI.
 * 
 * @author fcorneli
 * 
 */
public class Messages {

	private final ResourceBundle resourceBundle;

	public static enum MESSAGE_ID {
		LOADING("loading"), SECURITY_ERROR("securityError"), CARD_ERROR(
				"cardError"), GENERIC_ERROR("genericError"), DETECTING_CARD(
				"detectingCard"), INSERT_CARD_QUESTION("insertCardQuestion"), READING_IDENTITY(
				"readingIdentity"), TRANSMITTING_IDENTITY(
				"transmittingIdentity"), DONE("done"), PRIVACY_QUESTION(
				"privacyQuestion"), AUTHENTICATING("authenticating"), REMOVE_CARD(
				"removeCard"), SIGNING("signing"), SELECT_FILES("selectFiles"), DIGESTING_FILES(
				"digestingFiles"), COPY_ALL("copyAll"), MAIL("mail"), NO_MIDDLEWARE_ERROR(
				"noMiddlewareError"), PIN_BLOCKED("pinBlocked"), PIN_CHANGED(
				"pinChanged"), PIN_UNBLOCKED("pinUnblocked"), RETRIES_LEFT(
				"retriesLeft"), PIN_INCORRECT("pinIncorrect"), CONNECT_READER(
				"connectReader"), PIN_PAD("pinPad"), CURRENT_PIN("currentPin"), NEW_PIN(
				"newPin"), OK("ok"), CANCEL("cancel");

		private final String id;

		private MESSAGE_ID(String id) {
			this.id = id;
		}

		public String getId() {
			return this.id;
		}
	};

	public Messages(Locale locale) {
		this.resourceBundle = ResourceBundle.getBundle(
				"be.fedict.eid.applet.Messages", locale);
	}

	public String getMessage(MESSAGE_ID messageId) {
		String message = this.resourceBundle.getString(messageId.id);
		return message;
	}
}
