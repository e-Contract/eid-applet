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

package be.fedict.eid.applet.service.impl.tlv;

/**
 * Exception class thrown by a data convertor.
 * 
 * @see DataConvertor
 * 
 * @author fcorneli
 */
public class DataConvertorException extends Exception {
	private static final long serialVersionUID = 1L;

	/**
	 * Main constructor.
	 * 
	 * @param message
	 *            the exception message.
	 */
	public DataConvertorException(String message) {
		super(message);
	}
}