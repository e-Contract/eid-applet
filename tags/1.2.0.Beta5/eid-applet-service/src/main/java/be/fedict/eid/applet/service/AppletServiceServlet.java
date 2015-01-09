/*
 * eID Applet Project.
 * Copyright (C) 2008-2012 FedICT.
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

package be.fedict.eid.applet.service;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.impl.ServiceLocator;
import be.fedict.eid.applet.service.impl.handler.AuthSignResponseMessageHandler;
import be.fedict.eid.applet.service.impl.handler.AuthenticationDataMessageHandler;
import be.fedict.eid.applet.service.impl.handler.ClientEnvironmentMessageHandler;
import be.fedict.eid.applet.service.impl.handler.ContinueInsecureMessageHandler;
import be.fedict.eid.applet.service.impl.handler.FileDigestsDataMessageHandler;
import be.fedict.eid.applet.service.impl.handler.HandlesMessage;
import be.fedict.eid.applet.service.impl.handler.HelloMessageHandler;
import be.fedict.eid.applet.service.impl.handler.IdentityDataMessageHandler;
import be.fedict.eid.applet.service.impl.handler.InitParam;
import be.fedict.eid.applet.service.impl.handler.MessageHandler;
import be.fedict.eid.applet.service.impl.handler.SignCertificatesDataMessageHandler;
import be.fedict.eid.applet.service.impl.handler.SignatureDataMessageHandler;
import be.fedict.eid.applet.shared.AbstractProtocolMessage;

/**
 * The eID applet service Servlet. This servlet should be used by web
 * applications for secure communication between the Java EE servlet container
 * and the eID applet. This servlet will push attributes within the HTTP session
 * after a successful identification of the browser using via the eID applet.
 * 
 * <p>
 * The attribute that is pushed within the HTTP session per default is:
 * <code>eid.identity</code> of type {@link Identity}.
 * </p>
 * 
 * <p>
 * The address on the eID card can also be requested by setting the optional
 * <code>IncludeAddress</code> <code>init-param</code> to <code>true</code>. The
 * corresponding HTTP session attribute is called <code>eid.address</code> and
 * is of type {@link Address}.
 * </p>
 * 
 * <p>
 * The photo on the eID card can also be requested by setting the optional
 * <code>IncludePhoto</code> <code>init-param</code> to <code>true</code>. The
 * corresponding HTTP session attribute is called <code>eid.photo</code>.
 * </p>
 * 
 * <p>
 * More information on all available init-param configuration parameters is
 * available in the eID Applet developer's guide.
 * </p>
 * 
 * @author Frank Cornelis
 */
public class AppletServiceServlet extends AbstractAppletServiceServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(AppletServiceServlet.class);

	private static final Class<? extends MessageHandler<?>>[] MESSAGE_HANDLER_CLASSES = new Class[] {
			IdentityDataMessageHandler.class, HelloMessageHandler.class,
			ClientEnvironmentMessageHandler.class,
			AuthenticationDataMessageHandler.class,
			SignatureDataMessageHandler.class,
			FileDigestsDataMessageHandler.class,
			ContinueInsecureMessageHandler.class,
			SignCertificatesDataMessageHandler.class,
			AuthSignResponseMessageHandler.class };

	private Map<Class<?>, MessageHandler<?>> messageHandlers;

	public AppletServiceServlet() {
		super();
		LOG.debug("constructor");
	}

	@Override
	public void init(ServletConfig config) throws ServletException {
		super.init(config);

		LOG.debug("init");

		this.messageHandlers = new HashMap<Class<?>, MessageHandler<?>>();
		for (Class<? extends MessageHandler<?>> messageHandlerClass : MESSAGE_HANDLER_CLASSES) {
			HandlesMessage handlesMessageAnnotation = messageHandlerClass
					.getAnnotation(HandlesMessage.class);
			if (null == handlesMessageAnnotation) {
				throw new ServletException(
						"missing meta-data on message handler: "
								+ messageHandlerClass.getName());
			}
			Class<? extends AbstractProtocolMessage> protocolMessageClass = handlesMessageAnnotation
					.value();
			MessageHandler<?> messageHandler;
			try {
				messageHandler = messageHandlerClass.newInstance();
			} catch (Exception e) {
				throw new ServletException(
						"cannot create message handler instance");
			}
			this.messageHandlers.put(protocolMessageClass, messageHandler);
		}

		Collection<MessageHandler<?>> messageHandlers = this.messageHandlers
				.values();
		for (MessageHandler<?> messageHandler : messageHandlers) {
			try {
				injectInitParams(config, messageHandler);
			} catch (Exception e) {
				throw new ServletException(
						"error injecting init-param into message handler field: "
								+ e.getMessage(), e);
			}
			messageHandler.init(config);
		}
	}

	public static void injectInitParams(ServletConfig config,
			MessageHandler<?> messageHandler) throws ServletException,
			IllegalArgumentException, IllegalAccessException {
		Class<?> messageHandlerClass = messageHandler.getClass();
		Field[] fields = messageHandlerClass.getDeclaredFields();
		for (Field field : fields) {
			InitParam initParamAnnotation = field
					.getAnnotation(InitParam.class);
			if (null == initParamAnnotation) {
				continue;
			}
			String initParamName = initParamAnnotation.value();
			Class<?> fieldType = field.getType();
			field.setAccessible(true);
			if (ServiceLocator.class.equals(fieldType)) {
				/*
				 * We always inject a service locator.
				 */
				ServiceLocator<Object> fieldValue = new ServiceLocator<Object>(
						initParamName, config);
				field.set(messageHandler, fieldValue);
				continue;
			}
			String initParamValue = config.getInitParameter(initParamName);
			if (initParamAnnotation.required() && null == initParamValue) {
				throw new ServletException("missing required init-param: "
						+ initParamName + " for message handler:"
						+ messageHandlerClass.getName());
			}
			if (null == initParamValue) {
				continue;
			}
			if (Boolean.TYPE.equals(fieldType)) {
				LOG.debug("injecting boolean: " + initParamValue);
				Boolean fieldValue = Boolean.parseBoolean(initParamValue);
				field.set(messageHandler, fieldValue);
				continue;
			}
			if (String.class.equals(fieldType)) {
				field.set(messageHandler, initParamValue);
				continue;
			}
			if (InetAddress.class.equals(fieldType)) {
				InetAddress inetAddress;
				try {
					inetAddress = InetAddress.getByName(initParamValue);
				} catch (UnknownHostException e) {
					throw new ServletException("unknown host: "
							+ initParamValue);
				}
				field.set(messageHandler, inetAddress);
				continue;
			}
			if (Long.class.equals(fieldType)) {
				Long fieldValue = Long.parseLong(initParamValue);
				field.set(messageHandler, fieldValue);
				continue;
			}
			throw new ServletException("unsupported init-param field type: "
					+ fieldType.getName());
		}
	}

	@Override
	protected <T> MessageHandler<T> getMessageHandler(Class<T> messageClass) {
		return (MessageHandler<T>) this.messageHandlers.get(messageClass);
	}
}
