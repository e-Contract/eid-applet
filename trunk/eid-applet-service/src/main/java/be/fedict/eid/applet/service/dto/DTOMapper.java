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

import java.lang.reflect.Field;

/**
 * Data Transfer Object Mapper.
 * 
 * @author Frank Cornelis
 * 
 */
public class DTOMapper {

	/**
	 * Maps an object to an object of the given class.
	 * 
	 * @param <T>
	 *            the type of the class to map to.
	 * @param from
	 *            the object to map from.
	 * @param toClass
	 *            the class to map to.
	 * @return the mapped object.
	 */
	public <T> T map(Object from, Class<T> toClass) {
		if (null == from) {
			return null;
		}
		T to;
		try {
			to = toClass.newInstance();
		} catch (Exception e) {
			throw new RuntimeException("could not create new instance of "
					+ toClass.getName());
		}
		Class<?> fromClass = from.getClass();
		Field[] fromFields = fromClass.getDeclaredFields();
		for (Field fromField : fromFields) {
			Mapping mappingAnnotation = fromField.getAnnotation(Mapping.class);
			if (null == mappingAnnotation) {
				continue;
			}
			MapsTo[] mapsToAnnotations = mappingAnnotation.value();
			for (MapsTo mapsToAnnotation : mapsToAnnotations) {
				if (false == toClass.equals(mapsToAnnotation.value())) {
					continue;
				}
				String toFieldName = mapsToAnnotation.field();
				if (toFieldName.isEmpty()) {
					toFieldName = fromField.getName();
				}
				Field toField;
				try {
					toField = toClass.getDeclaredField(toFieldName);
				} catch (Exception e) {
					throw new RuntimeException("no such target field: "
							+ toFieldName);
				}
				Object value;
				try {
					value = fromField.get(from);
				} catch (Exception e) {
					throw new RuntimeException("could not read field: "
							+ fromField.getName());
				}
				Class<? extends ValueConvertor<?, ?>> valueConvertorClass = mapsToAnnotation
						.convertor();
				if (false == IdenticalValueConvertor.class
						.equals(valueConvertorClass)) {
					ValueConvertor<Object, Object> valueConvertor;
					try {
						valueConvertor = (ValueConvertor<Object, Object>) valueConvertorClass
								.newInstance();
					} catch (Exception e) {
						throw new RuntimeException(
								"could not instantiate value convertor: "
										+ valueConvertorClass.getName());
					}
					try {
						value = valueConvertor.convert(value);
					} catch (ValueConvertorException e) {
						throw new RuntimeException(
								"could not convert value of field: "
										+ fromField.getName());
					}
				}
				try {
					toField.set(to, value);
				} catch (Exception e) {
					throw new RuntimeException("could not write field "
							+ toFieldName + ": " + e.getMessage(), e);
				}
			}
		}
		return to;
	}
}
