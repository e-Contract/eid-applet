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

package be.fedict.eid.applet.service.dto;

/**
 * Interface for a value convertor component.
 * 
 * @author Frank Cornelis
 * 
 * @param <TO>
 *            the type to which to convert to.
 * @param <FROM>
 *            the type from which to convert.
 */
public interface ValueConvertor<FROM, TO> {
	/**
	 * Convert the given object to the convertor data type.
	 * 
	 * @param value
	 *            the object to convert.
	 * @return an object of the data convertor data type type.
	 * @throws ValueConvertorException
	 *             in case the conversion failed.
	 */
	TO convert(FROM value) throws ValueConvertorException;
}