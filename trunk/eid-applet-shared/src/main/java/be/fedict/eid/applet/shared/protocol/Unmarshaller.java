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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import be.fedict.eid.applet.shared.annotation.HttpBody;
import be.fedict.eid.applet.shared.annotation.HttpHeader;
import be.fedict.eid.applet.shared.annotation.MessageDiscriminator;
import be.fedict.eid.applet.shared.annotation.NotNull;
import be.fedict.eid.applet.shared.annotation.PostConstruct;
import be.fedict.eid.applet.shared.annotation.ProtocolVersion;
import be.fedict.eid.applet.shared.annotation.ValidateSemanticalIntegrity;

/**
 * Unmarshaller component is responsible for governing the process of converting
 * HTTP transported data streams to Java objects.
 * 
 * <p>
 * Keep this class stateless as it can be shared across different HTTP requests
 * inside AppletServiceServlet.
 * </p>
 * 
 * @author Frank Cornelis
 * 
 */
public class Unmarshaller {

	private String protocolMessageDiscriminatorHeaderName;

	private Map<String, Class<?>> protocolMessageClasses;

	private String protocolVersionHeaderName;

	private Integer protocolVersion;

	/**
	 * Main constructor.
	 * 
	 * @param catalog
	 */
	public Unmarshaller(ProtocolMessageCatalog catalog) {
		processMessageCatalog(catalog);
	}

	private void processMessageCatalog(ProtocolMessageCatalog catalog) {
		this.protocolMessageClasses = new HashMap<String, Class<?>>();
		List<Class<?>> messageClasses = catalog.getCatalogClasses();
		for (Class<?> messageClass : messageClasses) {
			Field discriminatorField = findDiscriminatorField(messageClass);

			HttpHeader httpHeaderAnnotation = discriminatorField
					.getAnnotation(HttpHeader.class);
			String discriminatorHttpHeaderName = httpHeaderAnnotation.value();
			if (null == this.protocolMessageDiscriminatorHeaderName) {
				this.protocolMessageDiscriminatorHeaderName = discriminatorHttpHeaderName;
			} else {
				if (false == this.protocolMessageDiscriminatorHeaderName
						.equals(discriminatorHttpHeaderName)) {
					throw new RuntimeException(
							"discriminator field not the same over all message classes");
				}
			}

			String discriminatorValue;
			try {
				discriminatorValue = (String) discriminatorField.get(null);
			} catch (Exception e) {
				throw new RuntimeException("error reading field: "
						+ e.getMessage());
			}
			if (this.protocolMessageClasses.containsValue(discriminatorValue)) {
				throw new RuntimeException(
						"discriminator field not unique for: "
								+ messageClass.getName());
			}
			this.protocolMessageClasses.put(discriminatorValue, messageClass);

			Field protocolVersionField = findProtocolVersionField(messageClass);
			httpHeaderAnnotation = protocolVersionField
					.getAnnotation(HttpHeader.class);
			String protocolVersionHttpHeaderName = httpHeaderAnnotation.value();
			if (null == this.protocolVersionHeaderName) {
				this.protocolVersionHeaderName = protocolVersionHttpHeaderName;
			} else {
				if (false == this.protocolVersionHeaderName
						.equals(protocolVersionHeaderName)) {
					throw new RuntimeException(
							"protocol version field not the same over all message classes");
				}
			}

			Integer protocolVersion;
			try {
				protocolVersion = (Integer) protocolVersionField.get(null);
			} catch (Exception e) {
				throw new RuntimeException("error reading field: "
						+ e.getMessage());
			}
			if (null == this.protocolVersion) {
				this.protocolVersion = protocolVersion;
			} else {
				if (false == this.protocolVersion.equals(protocolVersion)) {
					throw new RuntimeException(
							"protocol version not the same over all message classes");
				}
			}
		}
	}

	private Field findDiscriminatorField(Class<?> messageClass) {
		Field[] fields = messageClass.getFields();
		for (Field field : fields) {
			MessageDiscriminator messageDiscriminatorAnnotation = field
					.getAnnotation(MessageDiscriminator.class);
			if (null == messageDiscriminatorAnnotation) {
				continue;
			}
			if (Modifier.FINAL != (field.getModifiers() & Modifier.FINAL)) {
				throw new RuntimeException(
						"message discriminator should be final");
			}
			if (Modifier.STATIC != (field.getModifiers() & Modifier.STATIC)) {
				throw new RuntimeException(
						"message discriminator should be static");
			}
			if (false == String.class.equals(field.getType())) {
				throw new RuntimeException(
						"message discriminator should be a String");
			}
			HttpHeader httpHeaderAnnotation = field
					.getAnnotation(HttpHeader.class);
			if (null == httpHeaderAnnotation) {
				throw new RuntimeException(
						"message discriminator should be a HTTP header");
			}
			return field;
		}
		throw new RuntimeException("no message discriminator field found on "
				+ messageClass.getName());
	}

	private Field findProtocolVersionField(Class<?> messageClass) {
		Field[] fields = messageClass.getFields();
		for (Field field : fields) {
			ProtocolVersion protocolVersionAnnotation = field
					.getAnnotation(ProtocolVersion.class);
			if (null == protocolVersionAnnotation) {
				continue;
			}
			if (Modifier.FINAL != (field.getModifiers() & Modifier.FINAL)) {
				throw new RuntimeException(
						"protocol version field should be final");
			}
			if (Modifier.STATIC != (field.getModifiers() & Modifier.STATIC)) {
				throw new RuntimeException(
						"protocol version field should be static");
			}
			if (false == Integer.TYPE.equals(field.getType())) {
				throw new RuntimeException(
						"protocol version field should be an int");
			}
			HttpHeader httpHeaderAnnotation = field
					.getAnnotation(HttpHeader.class);
			if (null == httpHeaderAnnotation) {
				throw new RuntimeException(
						"protocol version field should be a HTTP header");
			}
			return field;
		}
		throw new RuntimeException("no protocol version field field found on "
				+ messageClass.getName());
	}

	/**
	 * Receive a certain transfer object from the given HTTP receiver component.
	 * 
	 * @param httpReceiver
	 * @return
	 */
	public Object receive(HttpReceiver httpReceiver) {
		/*
		 * Secure channel check
		 */
		if (false == httpReceiver.isSecure()) {
			throw new SecurityException("HTTP receiver over unsecure channel");
		}

		/*
		 * Message protocol check
		 */
		String protocolVersionHeader = httpReceiver
				.getHeaderValue(this.protocolVersionHeaderName);
		if (null == protocolVersionHeader) {
			throw new RuntimeException("no protocol version header");
		}
		Integer protocolVersion = Integer.parseInt(protocolVersionHeader);
		if (false == this.protocolVersion.equals(protocolVersion)) {
			throw new RuntimeException("protocol version mismatch");
		}

		/*
		 * Message discriminator
		 */
		String discriminatorValue = httpReceiver
				.getHeaderValue(this.protocolMessageDiscriminatorHeaderName);
		Class<?> protocolMessageClass = this.protocolMessageClasses
				.get(discriminatorValue);
		if (null == protocolMessageClass) {
			throw new RuntimeException("unsupported message: "
					+ discriminatorValue);
		}

		/*
		 * Create the message object
		 */
		Object transferObject;
		try {
			transferObject = protocolMessageClass.newInstance();
		} catch (Exception e) {
			throw new RuntimeException("error: " + e.getMessage(), e);
		}

		/*
		 * First inject all HTTP headers. Is also performing some syntactical
		 * input validation.
		 */
		try {
			injectHttpHeaderFields(httpReceiver, protocolMessageClass,
					transferObject);
		} catch (Exception e) {
			throw new RuntimeException("error: " + e.getMessage(), e);
		}

		/*
		 * Inject HTTP body.
		 */
		Field[] fields = protocolMessageClass.getFields();
		injectHttpBody(httpReceiver, transferObject, fields);

		/*
		 * Input validation.
		 */
		inputValidation(transferObject, fields);

		/*
		 * Semantical integrity validation.
		 */
		semanticValidation(protocolMessageClass, transferObject);

		/*
		 * PostConstruct semantics
		 */
		postConstructSemantics(protocolMessageClass, transferObject);

		return transferObject;
	}

	private void injectHttpBody(HttpReceiver httpReceiver,
			Object transferObject, Field[] fields) {
		Field bodyField = null;
		for (Field field : fields) {
			HttpBody httpBodyAnnotation = field.getAnnotation(HttpBody.class);
			if (null != httpBodyAnnotation) {
				if (null == bodyField) {
					bodyField = field;
				} else {
					throw new RuntimeException("multiple body fields detected");
				}
			}
		}
		if (null != bodyField) {
			byte[] body = httpReceiver.getBody();
			Object bodyValue;
			if (List.class.equals(bodyField.getType())) {
				List<String> bodyList = new LinkedList<String>();
				BufferedReader reader = new BufferedReader(
						new InputStreamReader(new ByteArrayInputStream(body)));
				String line;
				try {
					while (null != (line = reader.readLine())) {
						bodyList.add(line);
					}
				} catch (IOException e) {
					throw new RuntimeException("IO error: " + e.getMessage());
				}
				bodyValue = bodyList;
			} else {
				bodyValue = body;
			}
			try {
				bodyField.set(transferObject, bodyValue);
			} catch (Exception e) {
				throw new RuntimeException("error: " + e.getMessage(), e);
			}
		}
	}

	private void postConstructSemantics(Class<?> protocolMessageClass,
			Object transferObject) {
		Method[] methods = protocolMessageClass.getMethods();
		for (Method method : methods) {
			PostConstruct postConstructAnnotation = method
					.getAnnotation(PostConstruct.class);
			if (null != postConstructAnnotation) {
				try {
					method.invoke(transferObject, new Object[] {});
				} catch (InvocationTargetException e) {
					Throwable methodException = e.getTargetException();
					if (methodException instanceof RuntimeException) {
						RuntimeException runtimeException = (RuntimeException) methodException;
						/*
						 * We directly rethrow the runtime exception to have a
						 * cleaner stack trace.
						 */
						throw runtimeException;
					}
					throw new RuntimeException(
							"@PostConstruct method invocation error: "
									+ methodException.getMessage(),
							methodException);
				} catch (Exception e) {
					throw new RuntimeException("@PostConstruct error: "
							+ e.getMessage(), e);
				}
			}
		}
	}

	@SuppressWarnings("unchecked")
	private void semanticValidation(Class<?> protocolMessageClass,
			Object transferObject) {
		ValidateSemanticalIntegrity validateSemanticalIntegrity = protocolMessageClass
				.getAnnotation(ValidateSemanticalIntegrity.class);
		if (null != validateSemanticalIntegrity) {
			Class<? extends SemanticValidator<?>> validatorClass = validateSemanticalIntegrity
					.value();
			SemanticValidator validator;
			try {
				validator = validatorClass.newInstance();
			} catch (Exception e) {
				throw new RuntimeException("error: " + e.getMessage(), e);
			}
			try {
				validator.validate(transferObject);
			} catch (SemanticValidatorException e) {
				throw new RuntimeException("semantic validation error: "
						+ e.getMessage());
			}
		}
	}

	private void inputValidation(Object transferObject, Field[] fields) {
		for (Field field : fields) {
			NotNull notNullAnnotation = field.getAnnotation(NotNull.class);
			if (null == notNullAnnotation) {
				continue;
			}
			// XXX: doesn't make sense for primitive fields
			Object fieldValue;
			try {
				fieldValue = field.get(transferObject);
			} catch (Exception e) {
				throw new RuntimeException("error: " + e.getMessage(), e);
			}
			if (null == fieldValue) {
				throw new RuntimeException("field should not be null: "
						+ field.getName());
			}
		}
	}

	private void injectHttpHeaderFields(HttpReceiver httpReceiver,
			Class<?> protocolMessageClass, Object transferObject)
			throws IllegalArgumentException, IllegalAccessException {
		List<String> headerNames = httpReceiver.getHeaderNames();
		for (String headerName : headerNames) {
			Field httpHeaderField = findHttpHeaderField(protocolMessageClass,
					headerName);
			if (null != httpHeaderField) {
				String headerValue = httpReceiver.getHeaderValue(headerName);
				if (0 != (httpHeaderField.getModifiers() & Modifier.FINAL)) {
					/*
					 * In this case we must check that the value corresponds.
					 */
					String constantValue;
					if (String.class.equals(httpHeaderField.getType())) {
						constantValue = (String) httpHeaderField
								.get(transferObject);
					} else if (Integer.TYPE.equals(httpHeaderField.getType())) {
						constantValue = ((Integer) httpHeaderField
								.get(transferObject)).toString();
					} else {
						throw new RuntimeException("unsupported type: "
								+ httpHeaderField.getType().getName());
					}
					if (false == constantValue.equals(headerValue)) {
						throw new RuntimeException("constant value mismatch: "
								+ httpHeaderField.getName()
								+ "; expected value: " + constantValue
								+ "; actual value: " + headerValue);
					}
				} else {
					if (String.class.equals(httpHeaderField.getType())) {
						httpHeaderField.set(transferObject, headerValue);
					} else if (Integer.TYPE.equals(httpHeaderField.getType())
							|| Integer.class.equals(httpHeaderField.getType())) {
						Integer intValue = Integer.parseInt(headerValue);
						httpHeaderField.set(transferObject, intValue);
						// TODO make this type handling more generic
					} else if (Boolean.TYPE.equals(httpHeaderField.getType())
							|| Boolean.class.equals(httpHeaderField.getType())) {
						Boolean boolValue = Boolean.parseBoolean(headerValue);
						httpHeaderField.set(transferObject, boolValue);
					} else if (httpHeaderField.getType().isEnum()) {
						Enum<?> e = (Enum<?>) httpHeaderField.getType()
								.getEnumConstants()[0];
						Object value = e.valueOf(e.getClass(), headerValue);
						httpHeaderField.set(transferObject, value);
					} else {
						throw new RuntimeException(
								"unsupported http header field type: "
										+ httpHeaderField.getType());
					}
				}
			}
		}
	}

	private Field findHttpHeaderField(Class<?> protocolMessageClass,
			String headerName) {
		if (null == headerName) {
			throw new RuntimeException("header name should not be null");
		}
		Field[] fields = protocolMessageClass.getFields();
		for (Field field : fields) {
			HttpHeader httpHeaderAnnotation = field
					.getAnnotation(HttpHeader.class);
			if (null == httpHeaderAnnotation) {
				continue;
			}
			String fieldHttpHeaderName = httpHeaderAnnotation.value();
			/*
			 * Ignore cases since the HttpServletRequest class likes to do so.
			 */
			if (headerName.equalsIgnoreCase(fieldHttpHeaderName)) {
				return field;
			}
		}
		return null;
	}
}
