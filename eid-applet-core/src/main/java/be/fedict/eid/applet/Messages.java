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

package be.fedict.eid.applet;

import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import javax.swing.UIManager;

/**
 * Util class to manage the i18n messages used within the eID Applet UI.
 * 
 * @author Frank Cornelis
 * 
 */
public class Messages {

	public static final String RESOURCE_BUNDLE_NAME = "be.fedict.eid.applet.Messages";

	private final ResourceBundle resourceBundle;

	private final Locale locale;

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
				"newPin"), OK("ok"), CANCEL("cancel"), PUK_PAD("pukPad"), PIN_PAD_CHANGE(
				"pinPadChange"), KIOSK_MODE("kioskMode"), PIN_CHANGE(
				"pinChange"), PIN_UNBLOCK("pinUnblock"), PIN_PAD_MODIFY_OLD(
				"pinPadModifyOld"), PIN_PAD_MODIFY_NEW("pinPadModifyNew"), PIN_PAD_MODIFY_NEW_AGAIN(
				"pinPadModifyNewAgain"), DIAGNOSTIC_MODE("diagnosticMode"), CERTIFICATE_EXPIRED_ERROR(
				"certificateExpiredError"), CERTIFICATE_REVOKED_ERROR(
				"certificateRevokedError"), IDENTITY_INFO("identityInfo"),  IDENTITY_IDENTITY(
                                "identityIdentity"), IDENTITY_ADDRESS("identityAddress"), IDENTITY_PHOTO(
                                "identityPhoto"), DETAILS_BUTTON("detailsButtonText"), CANCEL_BUTTON(
				"cancelButtonText"), NO_BUTTON("noButtonText"), OK_BUTTON(
				"okButtonText"), YES_BUTTON("yesButtonText");

		private final String id;

		private MESSAGE_ID(String id) {
			this.id = id;
		}

		public String getId() {
			return this.id;
		}
	};

	public Messages(Locale locale) {
		this.locale = locale;
		ResourceBundle bundle;
		try {
			bundle = ResourceBundle
					.getBundle(RESOURCE_BUNDLE_NAME, this.locale);
		} catch (MissingResourceException e) {
			/*
			 * In case the selected locale and default system locale are not
			 * supported we default to english.
			 */
			bundle = ResourceBundle.getBundle(RESOURCE_BUNDLE_NAME,
					Locale.ENGLISH);
		}
		this.resourceBundle = bundle;

		UIManager.put("OptionPane.cancelButtonText",
				getMessage(MESSAGE_ID.CANCEL_BUTTON));
		UIManager.put("OptionPane.noButtonText",
				getMessage(MESSAGE_ID.NO_BUTTON));
		UIManager.put("OptionPane.okButtonText",
				getMessage(MESSAGE_ID.OK_BUTTON));
		UIManager.put("OptionPane.yesButtonText",
				getMessage(MESSAGE_ID.YES_BUTTON));
	}

	public String getMessage(MESSAGE_ID messageId) {
		String message = this.resourceBundle.getString(messageId.id);
		return message;
	}

	public Locale getLocale() {
		return this.locale;
	}
}
