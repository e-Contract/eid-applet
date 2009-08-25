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

package be.fedict.eid.applet.shared.protocol;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.util.List;

import be.fedict.eid.applet.shared.annotation.HttpBody;
import be.fedict.eid.applet.shared.annotation.HttpHeader;
import be.fedict.eid.applet.shared.annotation.NotNull;

/**
 * Transport component is responsible for governing the process of converting
 * Java objects into data streams using a HTTP transport component.
 * 
 * @author Frank Cornelis
 * 
 */
public class Transport {

	private Transport() {
		super();
	}

	/**
	 * Transfers the given data objects over the HTTP transport component.
	 * 
	 * @param dataObject
	 *            the data objects to transfer.
	 * @param httpTransmitter
	 *            the transport component.
	 */
	public static void transfer(Object dataObject,
			HttpTransmitter httpTransmitter) {
		/*
		 * Secure channel validation.
		 */
		if (false == httpTransmitter.isSecure()) {
			throw new SecurityException("applet service connection not trusted");
		}

		// TODO: semantic integrity validation

		Class<?> dataClass = dataObject.getClass();
		Field[] fields = dataClass.getFields();
		/*
		 * Input validation.
		 */
		try {
			inputValidation(dataObject, fields);
		} catch (Exception e) {
			throw new IllegalArgumentException("error: " + e.getMessage(), e);
		}

		/*
		 * Add HTTP headers.
		 */
		Field bodyField = addHeaders(dataObject, httpTransmitter, fields);

		/*
		 * Add HTTP body.
		 */
		addBody(dataObject, httpTransmitter, bodyField);
	}

	@SuppressWarnings("unchecked")
	private static void addBody(Object dataObject,
			HttpTransmitter httpTransmitter, Field bodyField) {
		if (null != bodyField) {
			Object bodyValue;
			try {
				bodyValue = bodyField.get(dataObject);
			} catch (Exception e) {
				throw new RuntimeException("error reading field: "
						+ bodyField.getName());
			}
			byte[] body;
			if (bodyValue instanceof List<?>) {
				List<String> bodyList = (List<String>) bodyValue;
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				PrintStream printStream = new PrintStream(baos);
				for (String bodyStr : bodyList) {
					printStream.println(bodyStr);
				}
				body = baos.toByteArray();
			} else {
				body = (byte[]) bodyValue;
			}
			/*
			 * The Content-Length header is required for IIS 6 and 7.
			 */
			httpTransmitter.addHeader("Content-Length", Integer
					.toString(body.length));
			httpTransmitter.setBody(body);
		} else {
			httpTransmitter.addHeader("Content-Length", "0");
		}
	}

	private static Field addHeaders(Object dataObject,
			HttpTransmitter httpTransmitter, Field[] fields) {
		Field bodyField = null;
		for (Field field : fields) {
			HttpBody httpBodyAnnotation = field.getAnnotation(HttpBody.class);
			if (null != httpBodyAnnotation) {
				if (null == bodyField) {
					bodyField = field;
				} else {
					throw new RuntimeException(
							"multiple @HttpBody fields detected");
				}
			}
			HttpHeader httpHeaderAnnotation = field
					.getAnnotation(HttpHeader.class);
			if (null == httpHeaderAnnotation) {
				continue;
			}
			Object fieldValue;
			try {
				fieldValue = field.get(dataObject);
			} catch (Exception e) {
				throw new RuntimeException("error reading field: "
						+ field.getName());
			}
			if (null != fieldValue) {
				String httpHeaderName = httpHeaderAnnotation.value();
				String httpHeaderValue;
				if (String.class.equals(field.getType())) {
					httpHeaderValue = (String) fieldValue;
				} else if (Integer.TYPE.equals(field.getType())
						|| Integer.class.equals(field.getType())) {
					httpHeaderValue = ((Integer) fieldValue).toString();
					// TODO: make this more generic
				} else if (Boolean.TYPE.equals(field.getType())
						|| Boolean.class.equals(field.getType())) {
					httpHeaderValue = ((Boolean) fieldValue).toString();
				} else {
					throw new RuntimeException("unsupported field type: "
							+ field.getType().getName());
				}
				httpTransmitter.addHeader(httpHeaderName, httpHeaderValue);
			}
		}
		return bodyField;
	}

	private static void inputValidation(Object dataObject, Field[] fields)
			throws IllegalArgumentException, IllegalAccessException {
		for (Field field : fields) {
			NotNull notEmptyAnnotation = field.getAnnotation(NotNull.class);
			if (null == notEmptyAnnotation) {
				continue;
			}
			Object fieldValue = field.get(dataObject);
			if (null == fieldValue) {
				throw new IllegalArgumentException(
						"input validation error: empty field: "
								+ field.getName());
			}
		}
	}
}
