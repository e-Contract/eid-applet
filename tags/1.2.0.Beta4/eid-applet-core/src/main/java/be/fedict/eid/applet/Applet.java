/*
 * eID Applet Project.
 * Copyright (C) 2008-2010 FedICT.
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

package be.fedict.eid.applet;

import java.applet.AppletContext;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.FlowLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.security.AccessController;
import java.security.Permission;
import java.security.PrivilegedAction;
import java.util.Locale;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JApplet;
import javax.swing.JButton;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JProgressBar;
import javax.swing.JRootPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

import be.fedict.eid.applet.Messages.MESSAGE_ID;

/**
 * The main class of the eID Applet. The {@link #init()} method is where it all
 * starts.
 * 
 * @author Frank Cornelis
 * @see Applet#init()
 */
public class Applet extends JApplet {

	private static final long serialVersionUID = 1L;

	public static final String TARGET_PAGE_PARAM = "TargetPage";

	public static final String CANCEL_PAGE_PARAM = "CancelPage";

	public static final String AUTHORIZATION_ERROR_PAGE_PARAM = "AuthorizationErrorPage";

	public static final String BACKGROUND_COLOR_PARAM = "BackgroundColor";

	public static final String FOREGROUND_COLOR_PARAM = "ForegroundColor";

	public static final String LANGUAGE_PARAM = "Language";

	public static final String MESSAGE_CALLBACK_PARAM = "MessageCallback";

	public static final String MESSAGE_CALLBACK_EX_PARAM = "MessageCallbackEx";

	public static final String HIDE_DETAILS_BUTTON_PARAM = "HideDetailsButton";

	private JStatusLabel statusLabel;

	private JTextArea detailMessages;

	private JProgressBar progressBar;

	private boolean securityConditionTrustedWebApp;

	private void setStatusMessage(final Status status,
			Messages.MESSAGE_ID messageId) {
		final String statusMessage = this.messages.getMessage(messageId);
		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				public void run() {
					Applet.this.statusLabel.setText(statusMessage);
					/*
					 * this helps screen readers, simply using setText() does
					 * not seem to work, at least not with Win2003 + JAB 2 +
					 * JSE6u20 + JAWS 10
					 */
					Applet.this.statusLabel.getAccessibleContext()
							.setAccessibleName(statusMessage);

					if (Status.ERROR == status) {
						Applet.this.statusLabel.setForeground(Color.RED);
						Applet.this.progressBar.setIndeterminate(false);
					}
					Applet.this.statusLabel.invalidate();
					if (false == Applet.this.hideDetailsButtonParam) {
						Applet.this.detailMessages.append(statusMessage + "\n");
						Applet.this.detailMessages
								.setCaretPosition(Applet.this.detailMessages
										.getDocument().getLength());
					} else {
						System.out.println(statusMessage);
					}
				}
			});
			Applet.this.invokeMessageCallback(status, messageId);
		} catch (Exception e) {
			// tja
		}
	}

	protected void invokeMessageCallback(Status status,
			Messages.MESSAGE_ID messageId) {
		if (null == this.messageCallbackParam
				&& null == this.messageCallbackExParam) {
			return;
		}
		ClassLoader classLoader = Applet.class.getClassLoader();
		Class<?> jsObjectClass;
		try {
			jsObjectClass = classLoader
					.loadClass("netscape.javascript.JSObject");
		} catch (ClassNotFoundException e) {
			String msg = "JSObject class not found";
			if (false == this.hideDetailsButtonParam) {
				this.detailMessages.append(msg + "\n");
				this.detailMessages.setCaretPosition(Applet.this.detailMessages
						.getDocument().getLength());
			} else {
				System.out.println(msg);
			}
			return;
		}
		try {
			Method getWindowMethod = jsObjectClass.getMethod("getWindow",
					new Class<?>[] { java.applet.Applet.class });
			Object jsObject = getWindowMethod.invoke(null, this);
			Method callMethod = jsObjectClass.getMethod("call", new Class<?>[] {
					String.class, Class.forName("[Ljava.lang.Object;") });
			if (null != this.messageCallbackParam) {
				addDetailMessage("invoking Javascript message callback: "
						+ this.messageCallbackParam);
				String statusMessage = this.messages.getMessage(messageId);
				callMethod.invoke(jsObject, this.messageCallbackParam,
						new Object[] { status.name(), statusMessage });
			}
			if (null != this.messageCallbackExParam) {
				addDetailMessage("invoking Javascript message callback (ex): "
						+ this.messageCallbackExParam);
				String statusMessage = this.messages.getMessage(messageId);
				callMethod.invoke(jsObject, this.messageCallbackExParam,
						new Object[] { status.name(), messageId.name(),
								statusMessage });
			}
		} catch (Exception e) {
			String msg = "error locating: JSObject.getWindow().call: "
					+ e.getMessage();
			if (false == this.hideDetailsButtonParam) {
				this.detailMessages.append(msg + "\n");
				this.detailMessages.setCaretPosition(Applet.this.detailMessages
						.getDocument().getLength());
			} else {
				System.out.println(msg);
			}
			return;
		}
	}

	@Override
	public void init() {
		try {
			javax.swing.SwingUtilities.invokeAndWait(new Runnable() {
				public void run() {
					initUI();
				}
			});
		} catch (Exception e) {
			System.err.println("initUI didn't successfully complete: "
					+ e.getMessage());
			StackTraceElement[] stackTrace = e.getStackTrace();
			for (StackTraceElement stackTraceElement : stackTrace) {
				System.err.println(stackTraceElement.getClassName() + "."
						+ stackTraceElement.getMethodName() + ":"
						+ stackTraceElement.getLineNumber());
			}
		}
	}

	private Thread workerThread;

	@Override
	public void start() {
		if (null == this.workerThread) {
			/*
			 * We start only once. Restart doesn't make sense for eID
			 * operations.
			 */
			this.workerThread = new Thread(new AppletThread());
			this.workerThread.start();
		} else {
			addDetailMessage("Restart detected.");
		}
	}

	private void gotoTargetPage() {
		String targetPageParam = getParameter(TARGET_PAGE_PARAM);
		if (null != targetPageParam) {
			AppletContext appletContext = getAppletContext();
			URL documentBase = getDocumentBase();
			try {
				URL targetUrl = new URL(documentBase, targetPageParam);
				addDetailMessage("Navigating to: " + targetUrl);
				appletContext.showDocument(targetUrl, "_self");
			} catch (MalformedURLException e) {
				addDetailMessage("URL error: " + e.getMessage());
			}
		}
	}

	private boolean gotoCancelPage() {
		String cancelPageParam = getParameter(CANCEL_PAGE_PARAM);
		if (null == cancelPageParam) {
			return false;
		}
		AppletContext appletContext = getAppletContext();
		URL documentBase = getDocumentBase();
		try {
			URL targetUrl = new URL(documentBase, cancelPageParam);
			addDetailMessage("Navigating to: " + targetUrl);
			appletContext.showDocument(targetUrl, "_self");
		} catch (MalformedURLException e) {
			addDetailMessage("URL error: " + e.getMessage());
		}
		return true;
	}

	private void gotoAuthorizationErrorPage() {
		String authorizationErrorPage = getParameter(AUTHORIZATION_ERROR_PAGE_PARAM);
		if (null == authorizationErrorPage) {
			return;
		}
		AppletContext appletContext = getAppletContext();
		URL documentBase = getDocumentBase();
		try {
			URL targetUrl = new URL(documentBase, authorizationErrorPage);
			addDetailMessage("Navigating to: " + targetUrl);
			appletContext.showDocument(targetUrl, "_self");
		} catch (MalformedURLException e) {
			addDetailMessage("URL error: " + e.getMessage());
		}
	}

	private void addDetailMessage(final String detailMessage) {
		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				public void run() {
					if (false == Applet.this.hideDetailsButtonParam) {
						Applet.this.detailMessages.append(detailMessage + "\n");
						Applet.this.detailMessages
								.setCaretPosition(Applet.this.detailMessages
										.getDocument().getLength());
					} else {
						System.out.println(detailMessage);
					}
				}
			});
		} catch (Exception e) {
			// tja
		}
	}

	@Override
	public AppletContext getAppletContext() {
		if (false == this.securityConditionTrustedWebApp) {
			throw new SecurityException("web application not trusted");
		}
		return super.getAppletContext();
	}

	@Override
	public String getParameter(String name) {
		if (false == this.securityConditionTrustedWebApp) {
			throw new SecurityException("web application not trusted");
		}
		return super.getParameter(name);
	}

	private void setBackgroundColor(Container container, Color backgroundColor) {
		for (Component component : container.getComponents()) {
			component.setBackground(backgroundColor);
			if (component instanceof Container) {
				setBackgroundColor((Container) component, backgroundColor);
			}
		}
		container.setBackground(backgroundColor);
	}

	private Messages messages;

	private String messageCallbackParam;

	private String messageCallbackExParam;

	private boolean hideDetailsButtonParam;

	private void initUI() {
		loadMessages();
		initStyle();

		this.messageCallbackParam = super.getParameter(MESSAGE_CALLBACK_PARAM);
		this.messageCallbackExParam = super
				.getParameter(MESSAGE_CALLBACK_EX_PARAM);

		String hideDetailsButtonParam = super
				.getParameter(HIDE_DETAILS_BUTTON_PARAM);
		if (null != hideDetailsButtonParam) {
			this.hideDetailsButtonParam = Boolean
					.parseBoolean(hideDetailsButtonParam);
		} else {
			this.hideDetailsButtonParam = false;
		}

		Container contentPane = this.getContentPane();
		contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.PAGE_AXIS));
		initStatusPanel(contentPane);
		contentPane.add(Box.createVerticalStrut(10));
		initProgressBar(contentPane);
		if (false == this.hideDetailsButtonParam) {
			contentPane.add(Box.createVerticalStrut(10));
			initDetailPanel(contentPane);
		}

		setupColors(contentPane);
	}

	private void initStyle() {
		try {
			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		} catch (Exception e) {
			// tja
		}
	}

	private void loadMessages() {
		/*
		 * super.getParameter to get around the security check.
		 */
		String languageParam = super.getParameter(LANGUAGE_PARAM);
		Locale locale;
		if (null != languageParam) {
			locale = new Locale(languageParam);
		} else {
			locale = this.getLocale();
		}
		/* for screen readers */
		JRootPane.setDefaultLocale(locale);
		this.messages = new Messages(locale);
	}

	private void initDetailPanel(Container container) {
		CardLayout cardLayout = new CardLayout();
		JPanel detailPanel = new JPanel(cardLayout);
		initDetailButton(detailPanel, cardLayout);
		initDetailMessages(detailPanel);
		container.add(detailPanel);
	}

	private void initDetailButton(final Container container,
			final CardLayout cardLayout) {
		JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		String msg = this.messages.getMessage(MESSAGE_ID.DETAILS_BUTTON);
		JButton detailButton = new JButton(msg + " >>");
		detailButton.getAccessibleContext().setAccessibleName(msg);

		detailButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent actionEvent) {
				cardLayout.next(container);
			}
		});
		panel.add(detailButton);
		container.add(panel, "button");
	}

	private void initDetailMessages(Container container) {
		this.detailMessages = new JTextArea(10, 80);
		this.detailMessages.setEditable(false);
		/* Detailed messages are only available in English */
		this.detailMessages.setLocale(Locale.ENGLISH);
		this.detailMessages.getAccessibleContext().setAccessibleDescription(
				"Detailed log messages");

		JPopupMenu popupMenu = new JPopupMenu();
		JMenuItem copyMenuItem = new JMenuItem(
				this.messages.getMessage(MESSAGE_ID.COPY_ALL));
		copyMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Toolkit toolkit = Toolkit.getDefaultToolkit();
				Clipboard clipboard = toolkit.getSystemClipboard();
				StringSelection stringSelection = new StringSelection(
						Applet.this.detailMessages.getText());
				clipboard.setContents(stringSelection, null);
			}
		});
		popupMenu.add(copyMenuItem);
		addMailMenuItem(popupMenu);
		this.detailMessages.setComponentPopupMenu(popupMenu);
		JScrollPane scrollPane = new JScrollPane(this.detailMessages,
				JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
				JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		container.add(scrollPane, "details");
	}

	private void initProgressBar(Container container) {
		this.progressBar = new JProgressBar();
		this.progressBar.setIndeterminate(true);
		container.add(this.progressBar);
	}

	private void initStatusPanel(Container container) {
		JPanel statusPanel = new JPanel();
		statusPanel.setLayout(new BoxLayout(statusPanel, BoxLayout.LINE_AXIS));

		String msg = this.messages.getMessage(MESSAGE_ID.LOADING);
		this.statusLabel = new JStatusLabel(msg);
		this.statusLabel.getAccessibleContext().setAccessibleName(msg);

		statusPanel.add(this.statusLabel);
		statusPanel.add(Box.createHorizontalGlue());
		container.add(statusPanel);
	}

	private void setupColors(Container container) {
		String backgroundColorParam = super
				.getParameter(BACKGROUND_COLOR_PARAM);
		Color backgroundColor;
		if (null != backgroundColorParam) {
			backgroundColor = Color.decode(backgroundColorParam);
		} else {
			backgroundColor = Color.WHITE;
		}
		setBackgroundColor(container, backgroundColor);

		String foregroundColorParam = super
				.getParameter(FOREGROUND_COLOR_PARAM);
		if (null != foregroundColorParam) {
			Color foregroundColor = Color.decode(foregroundColorParam);
			this.statusLabel.setForeground(foregroundColor);
			if (false == this.hideDetailsButtonParam) {
				this.detailMessages.setForeground(foregroundColor);
			}
		}
	}

	private void addMailMenuItem(JPopupMenu popupMenu) {
		Thread currentThread = Thread.currentThread();
		ClassLoader classLoader = currentThread.getContextClassLoader();
		Class<?> desktopClass;
		try {
			desktopClass = classLoader.loadClass("java.awt.Desktop");
		} catch (ClassNotFoundException e) {
			/*
			 * In this case the user cannot email to the FedICT service desk.
			 */
			return;
		}
		try {
			Method isDesktopSupportedMethod = desktopClass
					.getMethod("isDesktopSupported");
			Boolean desktopSupported = (Boolean) isDesktopSupportedMethod
					.invoke(null);
			if (false == desktopSupported) {
				return;
			}
			Method getDesktopMethod = desktopClass.getMethod("getDesktop");
			final Object desktop = getDesktopMethod.invoke(null);
			final Method mailMethod = desktopClass.getMethod("mail", URI.class);
			JMenuItem emailMenuItem = new JMenuItem(
					this.messages.getMessage(MESSAGE_ID.MAIL));
			emailMenuItem.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					String message = Applet.this.detailMessages.getText();
					try {
						URI mailUri = new URI("mailto:"
								+ URLEncoder.encode(
										"eid-applet@googlegroups.com", "UTF-8")
								+ "?subject="
								+ URLEncoder.encode("eID Applet Feedback",
										"UTF-8").replaceAll("\\+", "%20")
								+ "&body="
								+ URLEncoder.encode(message, "UTF-8")
										.replaceAll("\\+", "%20"));
						mailMethod.invoke(desktop, mailUri);
					} catch (Exception mailException) {
						Applet.this.addDetailMessage("error mailing message: "
								+ mailException.getMessage());
					}
				}
			});
			popupMenu.add(emailMenuItem);
		} catch (Exception e) {
			return;
		}
	}

	private class AppletThread implements Runnable {
		public void run() {
			addDetailMessage("eID Applet - Copyright (C) 2008-2013 FedICT.");
			addDetailMessage("Copyright (C) 2014 e-Contract.be BVBA.");
			addDetailMessage("Released under GNU LGPL version 3.0 license.");
			addDetailMessage("More info: http://code.google.com/p/eid-applet/");
			/*
			 * first check required applet permissions. prevents that
			 * cardTerminal.connect will trigger the security exception later on
			 */
			addDetailMessage("checking applet privileges...");
			SecurityManager securityManager = System.getSecurityManager();
			if (null == securityManager) {
				setStatusMessage(Status.ERROR, MESSAGE_ID.SECURITY_ERROR);
				addDetailMessage("no security manager found. not running as an applet?");
				return;
			}
			Object securityContext = securityManager.getSecurityContext();
			/*
			 * Next trick is to remove the dependency on the Java 6 runtime.
			 */
			String javaVersion = System.getProperty("java.version");
			if (javaVersion.startsWith("1.5")) {
				/*
				 * TODO: also check some 1.5 PKCS#11 required permission
				 * 
				 * Browsing the source code of OpenJDK you can see clearly that
				 * the Sun PKCS#11 wrapper is/was the one from IAIK. Funny that
				 * companies paid IAIK licenses while all that time Sun gave it
				 * away for free. Business seems to be all about tricking stupid
				 * people into spending money.
				 */
			} else {
				/*
				 * Java 1.6 and later.
				 */
				addDetailMessage("security manager permission check for java 1.6...");
				Permission permission;
				try {
					Class<?> cardPermissionClass = Class
							.forName("javax.smartcardio.CardPermission");
					Constructor<?> cardPermissionConstructor = cardPermissionClass
							.getConstructor(String.class, String.class);
					permission = (Permission) cardPermissionConstructor
							.newInstance("*", "*");
				} catch (Exception e) {
					setStatusMessage(Status.ERROR, MESSAGE_ID.GENERIC_ERROR);
					addDetailMessage("javax.smartcardio not available: "
							+ e.getMessage());
					return;
				}
				try {
					securityManager
							.checkPermission(permission, securityContext);
				} catch (SecurityException e) {
					setStatusMessage(Status.ERROR, MESSAGE_ID.SECURITY_ERROR);
					addDetailMessage("applet not authorized to access smart card. applet not signed?");
					return;
				}
				/*
				 * The Fedora IcedTea JRE browser plugin never gets the
				 * permissions right, even if the applet JAR has been signed.
				 */
			}

			/*
			 * Next check whether the user trusts the web application.
			 */
			addDetailMessage("checking web application trust...");
			URL documentBase = getDocumentBase();
			if (false == "https".equals(documentBase.getProtocol())) {
				if (false == "localhost".equals(documentBase.getHost())) {
					setStatusMessage(Status.ERROR, MESSAGE_ID.SECURITY_ERROR);
					addDetailMessage("web application not trusted.");
					addDetailMessage("use the web application via \"https\" instead of \"http\"");
					return;
				} else {
					addDetailMessage("trusting localhost web applications");
				}
			}
			URL codeBase = getCodeBase();
			if (false == "https".equals(codeBase.getProtocol())) {
				/*
				 * for reasons of performance a web designer might choose to
				 * keep the applet under http.
				 * 
				 * Notice that in this case Firefox 3 also gives a warning that
				 * the page contains partially unencrypted content. Of course we
				 * know that the integrity of the applet JAR is preserved anyhow
				 * because of the JAR digital signature.
				 */
				addDetailMessage("warning: web application (applet resource) not trusted.");
			}
			/*
			 * Mark the web application as trusted
			 */
			Applet.this.securityConditionTrustedWebApp = true;

			/*
			 * Next is to make sure we run privileged.
			 */
			AccessController.doPrivileged(new PrivilegedAction<Object>() {
				public Object run() {
					addDetailMessage("running privileged code...");
					Controller controller = new Controller(new AppletView(),
							new AppletRuntime(), Applet.this.messages);
					controller.run();
					return null;
				}
			});
		}
	}

	private class AppletRuntime implements Runtime {

		@Override
		public URL getDocumentBase() {
			return Applet.this.getDocumentBase();
		}

		@Override
		public String getParameter(String name) {
			return Applet.this.getParameter(name);
		}

		@Override
		public void gotoTargetPage() {
			Applet.this.gotoTargetPage();
		}

		@Override
		public Applet getApplet() {
			return Applet.this;
		}

		@Override
		public boolean gotoCancelPage() {
			return Applet.this.gotoCancelPage();
		}

		@Override
		public void gotoAuthorizationErrorPage() {
			Applet.this.gotoAuthorizationErrorPage();
		}
	}

	private class AppletView implements View {

		public void addDetailMessage(String detailMessage) {
			Applet.this.addDetailMessage(detailMessage);
		}

		public Component getParentComponent() {
			return Applet.this.getParentComponent();
		}

		public boolean privacyQuestion(boolean includeAddress,
				boolean includePhoto, String identityDataUsage) {
			return Applet.this.privacyQuestion(includeAddress, includePhoto,
					identityDataUsage);
		}

		public void setStatusMessage(Status status,
				Messages.MESSAGE_ID messageId) {
			Applet.this.setStatusMessage(status, messageId);
		}

		public void setProgressIndeterminate() {
			Applet.this.setProgressIndetermintate();
		}

		public void resetProgress(int max) {
			Applet.this.resetProgress(max);
		}

		public void increaseProgress() {
			Applet.this.increaseProgress();
		}

		@Override
		public void confirmAuthenticationSignature(String message) {
			Applet.this.confirmAuthenticationSignature(message);
		}

		@Override
		public int confirmSigning(String description, String digestAlgo) {
			return Applet.this.confirmSigning(description, digestAlgo);
		}
	}

	private boolean privacyQuestion(boolean includeAddress,
			boolean includePhoto, String identityDataUsage) {
		String msg = this.messages.getMessage(MESSAGE_ID.PRIVACY_QUESTION)
				+ "\n" + this.messages.getMessage(MESSAGE_ID.IDENTITY_INFO)
				+ ": " + this.messages.getMessage(MESSAGE_ID.IDENTITY_IDENTITY);
		if (includeAddress) {
			msg += ", " + this.messages.getMessage(MESSAGE_ID.IDENTITY_ADDRESS);
		}
		if (includePhoto) {
			msg += ", " + this.messages.getMessage(MESSAGE_ID.IDENTITY_PHOTO);
		}
		if (null != identityDataUsage) {
			msg += "\n" + this.messages.getMessage(MESSAGE_ID.USAGE) + ": "
					+ identityDataUsage;
		}
		int response = JOptionPane.showConfirmDialog(this, msg, "Privacy",
				JOptionPane.YES_NO_OPTION);
		return response == JOptionPane.YES_OPTION;
	}

	private int confirmSigning(String description, String digestAlgo) {
		String signatureCreationLabel = this.messages
				.getMessage(MESSAGE_ID.SIGNATURE_CREATION);
		String signQuestionLabel = this.messages
				.getMessage(MESSAGE_ID.SIGN_QUESTION);
		String signatureAlgoLabel = this.messages
				.getMessage(MESSAGE_ID.SIGNATURE_ALGO);
		int response = JOptionPane.showConfirmDialog(this.getParentComponent(),
				signQuestionLabel + " \"" + description + "\"?\n"
						+ signatureAlgoLabel + ": " + digestAlgo + " with RSA",
				signatureCreationLabel, JOptionPane.YES_NO_OPTION);
		return response;
	}

	private void confirmAuthenticationSignature(String message) {
		int response = JOptionPane.showConfirmDialog(this.getParentComponent(),
				message, "eID Authentication Signature",
				JOptionPane.YES_NO_OPTION);
		if (response != JOptionPane.YES_OPTION) {
			throw new SecurityException("user cancelled");
		}
	}

	private int progress;

	private void resetProgress(int max) {
		this.progressBar.setMinimum(0);
		this.progressBar.setMaximum(max);
		this.progressBar.setIndeterminate(false);
		this.progressBar.setValue(0);
		this.progress = 0;
	}

	private void setProgressIndetermintate() {
		this.progressBar.setIndeterminate(true);
	}

	private void increaseProgress() {
		this.progress++;
		this.progressBar.setValue(this.progress);
	}

	private Component getParentComponent() {
		return this;
	}
}
