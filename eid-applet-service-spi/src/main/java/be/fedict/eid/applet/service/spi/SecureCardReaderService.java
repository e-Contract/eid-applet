/*
 * eID Applet Project.
 * Copyright (C) 2008-2012 FedICT.
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

package be.fedict.eid.applet.service.spi;

/**
 * SPI for eID secure PIN pad card readers.
 * 
 * @author Frank Cornelis
 * 
 */
public interface SecureCardReaderService {

	public static final int TRANSACTION_MESSAGE_MAX_SIZE = 64;

	/**
	 * Gives back the message that should be displayed on the secure PIN pad
	 * reader as part of the authentication transaction.
	 * 
	 * @return the ASCII string message.
	 */
	String getTransactionMessage();
}
