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

package be.fedict.eid.applet.sc;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Observable;
import java.util.Set;

import javax.imageio.ImageIO;
import javax.smartcardio.ATR;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import javax.swing.DefaultListModel;
import javax.swing.ImageIcon;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.ListCellRenderer;

import be.fedict.eid.applet.DiagnosticTests;
import be.fedict.eid.applet.Dialogs;
import be.fedict.eid.applet.Dialogs.Pins;
import be.fedict.eid.applet.Messages;
import be.fedict.eid.applet.Messages.MESSAGE_ID;
import be.fedict.eid.applet.Status;
import be.fedict.eid.applet.View;

/**
 * Holds all functions related to eID card access over PC/SC.
 * 
 * This class required the Java 6 runtime to operate.
 * 
 * @author Frank Cornelis
 * 
 */
public class PcscEid extends Observable implements PcscEidSpi {

	public static final int MIN_PIN_SIZE = 4;

	public static final int MAX_PIN_SIZE = 12;

	public static final int PUK_SIZE = 6;

	private final static byte[] ATR_PATTERN = new byte[] { 0x3b, (byte) 0x98,
			0x00, 0x40, 0x00, (byte) 0x00, 0x00, 0x00, 0x01, 0x01, (byte) 0xad,
			0x13, 0x10 };

	private final static byte[] ATR_MASK = new byte[] { (byte) 0xff,
			(byte) 0xff, 0x00, (byte) 0xff, 0x00, 0x00, 0x00, 0x00,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xf0 };

	public static final byte[] IDENTITY_FILE_ID = new byte[] { 0x3F, 0x00,
			(byte) 0xDF, 0x01, 0x40, 0x31 };

	public static final byte[] IDENTITY_SIGN_FILE_ID = new byte[] { 0x3F, 0x00,
			(byte) 0xDF, 0x01, 0x40, 0x32 };

	public static final byte[] ADDRESS_FILE_ID = new byte[] { 0x3F, 0x00,
			(byte) 0xDF, 0x01, 0x40, 0x33 };

	public static final byte[] ADDRESS_SIGN_FILE_ID = new byte[] { 0x3F, 0x00,
			(byte) 0xDF, 0x01, 0x40, 0x34 };

	public static final byte[] PHOTO_FILE_ID = new byte[] { 0x3F, 0x00,
			(byte) 0xDF, 0x01, 0x40, 0x35 };

	public static final byte[] AUTHN_CERT_FILE_ID = new byte[] { 0x3F, 0x00,
			(byte) 0xDF, 0x00, 0x50, 0x38 };

	public static final byte[] SIGN_CERT_FILE_ID = new byte[] { 0x3F, 0x00,
			(byte) 0xDF, 0x00, 0x50, 0x39 };

	public static final byte[] CA_CERT_FILE_ID = new byte[] { 0x3F, 0x00,
			(byte) 0xDF, 0x00, 0x50, 0x3A };

	public static final byte[] ROOT_CERT_FILE_ID = new byte[] { 0x3F, 0x00,
			(byte) 0xDF, 0x00, 0x50, 0x3B };

	public static final byte[] RRN_CERT_FILE_ID = new byte[] { 0x3F, 0x00,
			(byte) 0xDF, 0x00, 0x50, 0x3C };

	public static final byte[] BELPIC_AID = new byte[] { (byte) 0xA0, 0x00,
			0x00, 0x01, 0x77, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35 };

	public static final byte[] APPLET_AID = new byte[] { (byte) 0xA0, 0x00,
			0x00, 0x00, 0x30, 0x29, 0x05, 0x70, 0x00, (byte) 0xAD, 0x13, 0x10,
			0x01, 0x01, (byte) 0xFF };

	private final View view;

	private final TerminalFactory terminalFactory;

	private final CardTerminals cardTerminals;

	private Dialogs dialogs;

	private Locale locale;

	public PcscEid(View view, Messages messages) {
		this.view = view;
		linuxPcscliteLibraryConfig();
		this.terminalFactory = TerminalFactory.getDefault();
		this.cardTerminals = this.terminalFactory.terminals();
		this.dialogs = new Dialogs(this.view, messages);
		this.locale = messages.getLocale();
	}

	/**
	 * Changes the messages, and thus the locale.
	 * 
	 * @param messages
	 */
	public void setMessages(Messages messages) {
		this.dialogs = new Dialogs(this.view, messages);
		this.locale = messages.getLocale();
	}

	/**
	 * Finds .so.version file on GNU/Linux. avoid guessing all GNU/Linux
	 * distros' library path configurations on 32 and 64-bit when working around
	 * the buggy libj2pcsc.so implementation based on JRE implementations adding
	 * the native library paths to the end of java.library.path
	 */
	private static File findLinuxNativeLibrary(String baseName, int version) {
		String nativeLibraryPaths = System.getProperty("java.library.path");
		if (nativeLibraryPaths == null) {
			return null;
		}

		String libFileName = System.mapLibraryName(baseName) + "." + version;
		for (String nativeLibraryPath : nativeLibraryPaths.split(":")) {
			File libraryFile = new File(nativeLibraryPath, libFileName);
			if (libraryFile.exists()) {
				return libraryFile;
			}
		}

		return null;
	}

	private void linuxPcscliteLibraryConfig() {
		String osName = System.getProperty("os.name");
		if (osName.startsWith("Linux")) {
			/*
			 * Workaround for Linux. Apparently the libj2pcsc.so from the JRE
			 * links to libpcsclite.so instead of libpcsclite.so.1. This can
			 * cause linking problems on Linux distributions that don't have the
			 * libpcsclite.so symbolic link.
			 * 
			 * See also: http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=529339
			 */

			this.view
					.addDetailMessage("[libj2pcsc.so workaround] Workaround for developer-only libj2pcsc.so on GNU/Linux Platforms enabled..");

			File libPcscLite = findLinuxNativeLibrary("pcsclite", 1);
			if (libPcscLite != null) {
				this.view
						.addDetailMessage("[libj2pcsc.so workaround] pcsclite found. Adjusting sun.security.smartcardio.library to ["
								+ libPcscLite.getAbsolutePath() + "]");
				System.setProperty("sun.security.smartcardio.library",
						libPcscLite.getAbsolutePath());
			} else {
				this.view
						.addDetailMessage("[libj2pcsc.so workaround] failed to find pcsclite.");
				String pathSought = System.getProperty("java.library.path");
				this.view
						.addDetailMessage("[libj2pcsc.so workaround] java.library.path=["
								+ (pathSought != null ? pathSought : "null")
								+ "]");
			}
		}
	}

	public List<String> getReaderList() {
		List<String> readerList = new LinkedList<String>();
		TerminalFactory factory = TerminalFactory.getDefault();
		CardTerminals cardTerminals = factory.terminals();
		List<CardTerminal> cardTerminalList;
		try {
			cardTerminalList = cardTerminals.list();
		} catch (CardException e) {
			/*
			 * Windows can give use a sun.security.smartcardio.PCSCException
			 * SCARD_E_NO_READERS_AVAILABLE here in case no card readers are
			 * connected to the system.
			 */
			this.view.addDetailMessage("error on card terminals list: "
					+ e.getMessage());
			this.view.addDetailMessage("no card readers connected?");
			Throwable cause = e.getCause();
			if (null != cause) {
				this.view.addDetailMessage("cause: " + cause.getMessage());
				this.view.addDetailMessage("cause type: "
						+ cause.getClass().getName());
			}
			return readerList;
		}
		for (CardTerminal cardTerminal : cardTerminalList) {
			readerList.add(cardTerminal.getName());
		}
		return readerList;
	}

	public byte[] readFile(byte[] fileId) throws CardException, IOException {
		selectFile(fileId);
		byte[] data = readBinary();
		return data;
	}

	public void close() {
		try {
			// this.card.endExclusive();
			this.card.disconnect(true);
		} catch (CardException e) {
			/*
			 * No need to propagate this further since we already have what we
			 * came for.
			 */
			this.view.addDetailMessage("error disconnecting card: "
					+ e.getMessage());
		}
	}

	private static final int BLOCK_SIZE = 0xff;

	private byte[] readBinary() throws CardException, IOException {
		int offset = 0;
		this.view.addDetailMessage("read binary");
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] data;
		do {
			CommandAPDU readBinaryApdu = new CommandAPDU(0x00, 0xB0,
					offset >> 8, offset & 0xFF, BLOCK_SIZE);
			ResponseAPDU responseApdu = transmit(readBinaryApdu);
			int sw = responseApdu.getSW();
			if (0x6B00 == sw) {
				/*
				 * Wrong parameters (offset outside the EF) End of file reached.
				 * Can happen in case the file size is a multiple of 0xff bytes.
				 */
				break;
			}
			if (0x9000 != sw) {
				throw new IOException("APDU response error: "
						+ responseApdu.getSW());
			}
			/*
			 * Notify our progress observers.
			 */
			setChanged();
			notifyObservers();

			/*
			 * Introduce some delay for old Belpic V1 eID cards.
			 */
			// try {
			// Thread.sleep(50);
			// } catch (InterruptedException e) {
			// throw new RuntimeException("sleep error: " + e.getMessage(), e);
			// }
			data = responseApdu.getData();
			baos.write(data);
			offset += data.length;
		} while (BLOCK_SIZE == data.length);
		return baos.toByteArray();
	}

	private Card card;

	public Card getCard() {
		return this.card;
	}

	private CardChannel cardChannel;

	private CardTerminal cardTerminal;

	public CardChannel getCardChannel() {
		return this.cardChannel;
	}

	public boolean hasCardReader() {
		try {
			List<CardTerminal> cardTerminalList = this.cardTerminals.list();
			return false == cardTerminalList.isEmpty();
		} catch (CardException e) {
			this.view.addDetailMessage("card terminals list error: "
					+ e.getMessage());
			return false;
		}
	}

	public void waitForCardReader() {
		while (false == hasCardReader()) {
			try {
				Thread.sleep(500);
			} catch (InterruptedException e) {
				throw new RuntimeException(e);
			}
		}
	}

	public boolean isEidPresent() throws CardException {
		List<CardTerminal> cardTerminalList;
		try {
			cardTerminalList = this.cardTerminals.list();
		} catch (CardException e) {
			this.view.addDetailMessage("card terminals list error: "
					+ e.getMessage());
			this.view.addDetailMessage("no card readers connected?");
			Throwable cause = e.getCause();
			if (null != cause) {
				/*
				 * Windows can give us a sun.security.smartcardio.PCSCException
				 * SCARD_E_NO_READERS_AVAILABLE when no card readers are
				 * connected to the system.
				 */
				this.view.addDetailMessage("cause: " + cause.getMessage());
				this.view.addDetailMessage("cause type: "
						+ cause.getClass().getName());
				if ("SCARD_E_NO_READERS_AVAILABLE".equals(cause.getMessage())) {
					/*
					 * Windows platform.
					 */
					this.view.addDetailMessage("no reader available");
				}
			}
			return false;
		}
		Set<CardTerminal> eIDCardTerminals = new HashSet<CardTerminal>();
		for (CardTerminal cardTerminal : cardTerminalList) {
			this.view.addDetailMessage("Scanning card terminal: "
					+ cardTerminal.getName());
			if (cardTerminal.isCardPresent()) {
				Card card;
				try {
					/*
					 * eToken is not using T=0 apparently, hence the need for an
					 * explicit CardException catch
					 */
					card = cardTerminal.connect("T=0");
					/*
					 * The exclusive card lock in combination with reset at
					 * disconnect and some sleeps seems to fix the
					 * SCARD_E_SHARING_VIOLATION issue.
					 */
					card.beginExclusive();
				} catch (CardException e) {
					this.view.addDetailMessage("could not connect to card: "
							+ e.getMessage());
					continue;
				}
				ATR atr = card.getATR();
				if (matchesEidAtr(atr)) {
					eIDCardTerminals.add(cardTerminal);
				} else {
					byte[] atrBytes = atr.getBytes();
					StringBuffer atrStringBuffer = new StringBuffer();
					for (byte atrByte : atrBytes) {
						atrStringBuffer.append(Integer
								.toHexString(atrByte & 0xff));
					}
					this.view
							.addDetailMessage("not a supported eID card. ATR= "
									+ atrStringBuffer);
				}
				card.endExclusive(); // SCARD_E_SHARING_VIOLATION fix
				card.disconnect(true);
			}
		}
		if (eIDCardTerminals.isEmpty()) {
			return false;
		}
		if (eIDCardTerminals.size() == 1) {
			this.cardTerminal = eIDCardTerminals.iterator().next();
		} else {
			try {
				this.cardTerminal = selectCardTerminal(eIDCardTerminals);
			} catch (IOException e) {
				this.view.addDetailMessage("error: " + e.getMessage());
				return false;
			}
		}
		if (null == this.cardTerminal) {
			/*
			 * In case the card terminal selection was canceled.
			 */
			return false;
		}
		this.view.addDetailMessage("eID card detected in card terminal : "
				+ this.cardTerminal.getName());
		this.card = this.cardTerminal.connect("T=0");
		this.card.beginExclusive();
		this.cardChannel = card.getBasicChannel();
		return true;
	}

	private static class ListData {
		private CardTerminal cardTerminal;
		private BufferedImage photo;

		public ListData(CardTerminal cardTerminal, BufferedImage photo) {
			this.cardTerminal = cardTerminal;
			this.photo = photo;
		}

		public CardTerminal getCardTerminal() {
			return this.cardTerminal;
		}

		public BufferedImage getPhoto() {
			return this.photo;
		}
	}

	private static class EidListCellRenderer extends JPanel implements
			ListCellRenderer {

		private static final long serialVersionUID = 1L;

		public Component getListCellRendererComponent(JList list, Object value,
				int index, boolean isSelected, boolean cellHasFocus) {
			JPanel panel = new JPanel();
			ListData listData = (ListData) value;
			panel.setLayout(new FlowLayout(FlowLayout.LEFT));
			JLabel photoLabel = new JLabel(new ImageIcon(listData.getPhoto()));
			panel.add(photoLabel);
			JLabel nameLabel = new JLabel(listData.getCardTerminal().getName());
			if (isSelected) {
				panel.setBackground(list.getSelectionBackground());
			} else {
				panel.setBackground(list.getBackground());
			}
			panel.add(nameLabel);
			return panel;
		}
	}

	private CardTerminal selectCardTerminal(Set<CardTerminal> eIDCardTerminals)
			throws CardException, IOException {
		this.view.addDetailMessage("multiple eID card detected...");
		DefaultListModel listModel = new DefaultListModel();
		for (CardTerminal cardTerminal : eIDCardTerminals) {
			this.cardTerminal = cardTerminal;
			this.card = this.cardTerminal.connect("T=0");
			this.card.beginExclusive();
			this.cardChannel = this.card.getBasicChannel();

			this.view.addDetailMessage("reading photo from: "
					+ this.cardTerminal.getName());
			byte[] photoFile = readFile(PHOTO_FILE_ID);
			BufferedImage photo = ImageIO.read(new ByteArrayInputStream(
					photoFile));
			listModel.addElement(new ListData(cardTerminal, photo));

			this.card.endExclusive(); // SCARD_E_SHARING_VIOLATION fix
			this.card.disconnect(true);
		}

		final JDialog dialog = new JDialog((Frame) null, "Select eID card",
				true);
		final ListData selectedListData = new ListData(null, null);
		dialog.setLayout(new BorderLayout());

		JList list = new JList(listModel);
		list.setCellRenderer(new EidListCellRenderer());
		dialog.getContentPane().add(list);

		MouseListener mouseListener = new MouseAdapter() {
			public void mouseClicked(MouseEvent mouseEvent) {
				JList theList = (JList) mouseEvent.getSource();
				if (mouseEvent.getClickCount() == 2) {
					int index = theList.locationToIndex(mouseEvent.getPoint());
					if (index >= 0) {
						Object object = theList.getModel().getElementAt(index);
						ListData listData = (ListData) object;
						selectedListData.cardTerminal = listData.cardTerminal;
						selectedListData.photo = listData.photo;
						dialog.dispose();
					}
				}
			}
		};
		list.addMouseListener(mouseListener);

		dialog.pack();
		dialog.setLocationRelativeTo(this.view.getParentComponent());
		dialog.setResizable(false);

		dialog.setVisible(true);

		return selectedListData.getCardTerminal();
	}

	private void selectFile(byte[] fileId) throws CardException,
			FileNotFoundException {
		this.view.addDetailMessage("selecting file");
		CommandAPDU selectFileApdu = new CommandAPDU(0x00, 0xA4, 0x08, 0x0C,
				fileId);
		ResponseAPDU responseApdu = transmit(selectFileApdu);
		if (0x9000 != responseApdu.getSW()) {
			throw new FileNotFoundException(
					"wrong status word after selecting file: "
							+ Integer.toHexString(responseApdu.getSW()));
		}
		try {
			// SCARD_E_SHARING_VIOLATION fix
			Thread.sleep(20);
		} catch (InterruptedException e) {
			throw new RuntimeException("sleep error: " + e.getMessage());
		}
	}

	private boolean matchesEidAtr(ATR atr) {
		byte[] atrBytes = atr.getBytes();
		if (atrBytes.length != ATR_PATTERN.length) {
			return false;
		}
		for (int idx = 0; idx < atrBytes.length; idx++) {
			atrBytes[idx] &= ATR_MASK[idx];
		}
		if (Arrays.equals(atrBytes, ATR_PATTERN)) {
			return true;
		}
		return false;
	}

	public void waitForEidPresent() throws CardException, InterruptedException {
		while (true) {
			try {
				this.cardTerminals.waitForChange();
			} catch (CardException e) {
				this.view.addDetailMessage("card error: " + e.getMessage());
				Throwable cause = e.getCause();
				if (null != cause) {
					if ("SCARD_E_NO_READERS_AVAILABLE".equals(cause
							.getMessage())) {
						/*
						 * sun.security.smartcardio.PCSCException
						 * 
						 * Windows platform.
						 */
						this.view.addDetailMessage("no readers available.");
					}
				}
				this.view.addDetailMessage("sleeping...");
				Thread.sleep(1000);
			} catch (IllegalStateException e) {
				this.view.addDetailMessage("no terminals at all. sleeping...");
				this.view
						.addDetailMessage("Maybe you should connect a smart card reader?");
				if (System.getProperty("os.name").startsWith("Linux")) {
					this.view
							.addDetailMessage("Maybe the pcscd service is not running?");
				}
				Thread.sleep(1000);
			}
			Thread.sleep(50); // SCARD_E_SHARING_VIOLATION fix
			if (isEidPresent()) {
				return;
			}
		}
	}

	public void removeCard() throws CardException {
		/*
		 * Next doesn't work all the time.
		 */
		// this.cardTerminal.waitForCardAbsent(0);
		while (isCardStillPresent()) {
			try {
				Thread.sleep(100);
			} catch (InterruptedException e) {
				this.view.addDetailMessage("sleep error: " + e.getMessage());
			}
		}
	}

	public boolean isCardStillPresent() throws CardException {
		return this.cardTerminal.isCardPresent();
	}

	public void yieldExclusive(boolean yield) throws CardException {
		if (yield) {
			getCard().endExclusive();
		} else {
			getCard().beginExclusive();
		}
	}

	public List<X509Certificate> getAuthnCertificateChain()
			throws CardException, IOException, CertificateException {
		List<X509Certificate> authnCertificateChain = new LinkedList<X509Certificate>();
		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");

		this.view.addDetailMessage("reading authn certificate...");
		byte[] authnCertFile = readFile(AUTHN_CERT_FILE_ID);
		X509Certificate authnCert = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(authnCertFile));
		authnCertificateChain.add(authnCert);

		this.view.addDetailMessage("reading Citizen CA certificate...");
		byte[] citizenCaCertFile = readFile(CA_CERT_FILE_ID);
		X509Certificate citizenCaCert = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(citizenCaCertFile));
		authnCertificateChain.add(citizenCaCert);

		this.view.addDetailMessage("reading Root CA certificate...");
		byte[] rootCaCertFile = readFile(ROOT_CERT_FILE_ID);
		X509Certificate rootCaCert = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(rootCaCertFile));
		authnCertificateChain.add(rootCaCert);

		return authnCertificateChain;
	}

	public static final byte FEATURE_VERIFY_PIN_START_TAG = 0x01;
	public static final byte FEATURE_VERIFY_PIN_FINISH_TAG = 0x02;
	public static final byte FEATURE_MODIFY_PIN_START_TAG = 0x03;
	public static final byte FEATURE_MODIFY_PIN_FINISH_TAG = 0x04;
	public static final byte FEATURE_GET_KEY_PRESSED_TAG = 0x05;
	public static final byte FEATURE_VERIFY_PIN_DIRECT_TAG = 0x06;
	public static final byte FEATURE_MODIFY_PIN_DIRECT_TAG = 0x07;

	private Integer getFeature(byte featureTag) {
		this.view.addDetailMessage("CCID GET_FEATURE IOCTL...");
		int ioctl;
		String osName = System.getProperty("os.name");
		if (osName.startsWith("Windows")) {
			ioctl = (0x31 << 16 | (3400) << 2);
		} else {
			ioctl = 0x42000D48;
		}
		byte[] features;
		try {
			features = this.card.transmitControlCommand(ioctl, new byte[0]);
		} catch (CardException e) {
			this.view.addDetailMessage("GET_FEATURES IOCTL error: "
					+ e.getMessage());
			return null;
		}
		if (0 == features.length) {
			return null;
		}
		Integer feature = findFeature(featureTag, features);
		return feature;
	}

	private Integer findFeature(byte featureTag, byte[] features) {
		int idx = 0;
		while (idx < features.length) {
			byte tag = features[idx];
			idx++;
			idx++;
			if (featureTag == tag) {
				int feature = 0;
				for (int count = 0; count < 3; count++) {
					feature |= features[idx] & 0xff;
					idx++;
					feature <<= 8;
				}
				feature |= features[idx] & 0xff;
				return feature;
			}
			idx += 4;
		}
		return null;
	}

	public byte[] sign(byte[] digestValue, String digestAlgo, byte keyId,
			boolean requireSecureReader) throws CardException, IOException,
			InterruptedException {
		Integer directPinVerifyFeature = getFeature(FEATURE_VERIFY_PIN_DIRECT_TAG);
		Integer verifyPinStartFeature = getFeature(FEATURE_VERIFY_PIN_START_TAG);

		if (requireSecureReader && null == directPinVerifyFeature
				&& null == verifyPinStartFeature) {
			throw new SecurityException("not a secure reader");
		}

		// select the key
		this.view.addDetailMessage("selecting key...");
		CommandAPDU setApdu = new CommandAPDU(0x00, 0x22, 0x41, 0xB6,
				new byte[] { 0x04, // length of following data
						(byte) 0x80, // algo ref
						0x01, // rsa pkcs#1
						(byte) 0x84, // tag for private key ref
						keyId });
		ResponseAPDU responseApdu = transmit(setApdu);
		if (0x9000 != responseApdu.getSW()) {
			throw new RuntimeException("SELECT error");
		}

		ByteArrayOutputStream digestInfo = new ByteArrayOutputStream();
		if ("SHA-1".equals(digestAlgo) || "SHA1".equals(digestAlgo)) {
			digestInfo.write(Constants.SHA1_DIGEST_INFO_PREFIX);
		} else if ("SHA-224".equals(digestAlgo)) {
			digestInfo.write(Constants.SHA224_DIGEST_INFO_PREFIX);
		} else if ("SHA-256".equals(digestAlgo)) {
			digestInfo.write(Constants.SHA256_DIGEST_INFO_PREFIX);
		} else if ("SHA-384".equals(digestAlgo)) {
			digestInfo.write(Constants.SHA384_DIGEST_INFO_PREFIX);
		} else if ("SHA-512".equals(digestAlgo)) {
			digestInfo.write(Constants.SHA512_DIGEST_INFO_PREFIX);
		} else if ("RIPEMD160".equals(digestAlgo)) {
			digestInfo.write(Constants.RIPEMD160_DIGEST_INFO_PREFIX);
		} else if ("RIPEMD128".equals(digestAlgo)) {
			digestInfo.write(Constants.RIPEMD128_DIGEST_INFO_PREFIX);
		} else if ("RIPEMD256".equals(digestAlgo)) {
			digestInfo.write(Constants.RIPEMD256_DIGEST_INFO_PREFIX);
		} else {
			throw new RuntimeException("digest also not supported: "
					+ digestAlgo);
		}
		digestInfo.write(digestValue);
		CommandAPDU computeDigitalSignatureApdu = new CommandAPDU(0x00, 0x2A,
				0x9E, 0x9A, digestInfo.toByteArray());

		this.view.addDetailMessage("computing digital signature...");
		responseApdu = transmit(computeDigitalSignatureApdu);
		if (0x9000 == responseApdu.getSW()) {
			/*
			 * OK, we could use the card PIN caching feature.
			 * 
			 * Notice that the card PIN caching also works when first doing an
			 * authentication after a non-repudiation signature.
			 */
			byte[] signatureValue = responseApdu.getData();
			return signatureValue;
		}
		if (0x6982 != responseApdu.getSW()) {
			this.view.addDetailMessage("SW: "
					+ Integer.toHexString(responseApdu.getSW()));
			throw new RuntimeException("compute digital signature error");
		}
		/*
		 * 0x6982 = Security status not satisfied, so we do a PIN verification
		 * before retrying.
		 */
		this.view.addDetailMessage("PIN verification required...");

		verifyPin(directPinVerifyFeature, verifyPinStartFeature);

		this.view.addDetailMessage("computing digital signature...");
		responseApdu = cardChannel.transmit(computeDigitalSignatureApdu);
		if (0x9000 != responseApdu.getSW()) {
			throw new RuntimeException("compute digital signature error: "
					+ Integer.toHexString(responseApdu.getSW()));
		}

		byte[] signatureValue = responseApdu.getData();
		return signatureValue;
	}

	public void verifyPin() throws IOException, CardException,
			InterruptedException {
		Integer directPinVerifyFeature = getFeature(FEATURE_VERIFY_PIN_DIRECT_TAG);
		Integer verifyPinStartFeature = getFeature(FEATURE_VERIFY_PIN_START_TAG);
		verifyPin(directPinVerifyFeature, verifyPinStartFeature);
	}

	private void verifyPin(Integer directPinVerifyFeature,
			Integer verifyPinStartFeature) throws IOException, CardException,
			InterruptedException {
		ResponseAPDU responseApdu;
		int retriesLeft = -1;
		do {
			if (null != directPinVerifyFeature) {
				responseApdu = verifyPinDirect(retriesLeft,
						directPinVerifyFeature);
			} else if (null != verifyPinStartFeature) {
				responseApdu = verifyPin(retriesLeft, verifyPinStartFeature);
			} else {
				responseApdu = verifyPin(retriesLeft);
			}
			if (0x9000 != responseApdu.getSW()) {
				this.view.addDetailMessage("VERIFY_PIN error");
				this.view.addDetailMessage("SW: "
						+ Integer.toHexString(responseApdu.getSW()));
				if (0x6983 == responseApdu.getSW()) {
					this.dialogs.showPinBlockedDialog();
					throw new RuntimeException("eID card blocked!");
				}
				if (0x63 != responseApdu.getSW1()) {
					this.view.addDetailMessage("PIN verification error.");
					throw new RuntimeException("PIN verification error.");
				}
				retriesLeft = responseApdu.getSW2() & 0xf;
				this.view.addDetailMessage("retries left: " + retriesLeft);
			}
		} while (0x9000 != responseApdu.getSW());
	}

	private ResponseAPDU verifyPin(int retriesLeft,
			Integer verifyPinStartFeature) throws IOException, CardException,
			InterruptedException {
		this.view.addDetailMessage("CCID verify PIN start/end sequence...");
		byte[] verifyCommandData = createPINVerificationDataStructure(0x20);
		this.dialogs.showPINPadFrame(retriesLeft);
		try {
			int getKeyPressedFeature = getFeature(FEATURE_GET_KEY_PRESSED_TAG);
			this.card.transmitControlCommand(verifyPinStartFeature,
					verifyCommandData);

			ccidWaitForOK(getKeyPressedFeature);
		} finally {
			this.dialogs.disposePINPadFrame();
		}
		int verifyPinFinishIoctl = getFeature(FEATURE_VERIFY_PIN_FINISH_TAG);
		byte[] verifyPinFinishResult = this.card.transmitControlCommand(
				verifyPinFinishIoctl, new byte[0]);
		ResponseAPDU responseApdu = new ResponseAPDU(verifyPinFinishResult);
		return responseApdu;
	}

	private ResponseAPDU verifyPinDirect(int retriesLeft,
			Integer directPinVerifyFeature) throws IOException, CardException {
		this.view.addDetailMessage("direct PIN verification...");
		byte[] verifyCommandData = createPINVerificationDataStructure(0x20);
		this.dialogs.showPINPadFrame(retriesLeft);
		byte[] result;
		try {
			result = this.card.transmitControlCommand(directPinVerifyFeature,
					verifyCommandData);
		} finally {
			this.dialogs.disposePINPadFrame();
		}
		ResponseAPDU responseApdu = new ResponseAPDU(result);
		if (0x6401 == responseApdu.getSW()) {
			this.view.addDetailMessage("canceled by user");
			throw new SecurityException("canceled by user");
		} else if (0x6400 == responseApdu.getSW()) {
			this.view.addDetailMessage("PIN pad timeout");
		}
		return responseApdu;
	}

	private ResponseAPDU verifyPukDirect(int retriesLeft,
			Integer directPinVerifyFeature) throws IOException, CardException {
		this.view.addDetailMessage("direct PUK verification...");
		byte[] verifyCommandData = createPINVerificationDataStructure(0x2C);
		this.dialogs.showPUKPadFrame(retriesLeft);
		byte[] result;
		try {
			result = this.card.transmitControlCommand(directPinVerifyFeature,
					verifyCommandData);
		} finally {
			this.dialogs.disposePINPadFrame();
		}
		ResponseAPDU responseApdu = new ResponseAPDU(result);
		if (0x6401 == responseApdu.getSW()) {
			this.view.addDetailMessage("canceled by user");
			throw new SecurityException("canceled by user");
		} else if (0x6400 == responseApdu.getSW()) {
			this.view.addDetailMessage("PIN pad timeout");
		}
		return responseApdu;
	}

	private byte[] createPINVerificationDataStructure(int apduIns)
			throws IOException {
		ByteArrayOutputStream verifyCommand = new ByteArrayOutputStream();
		verifyCommand.write(30); // bTimeOut
		verifyCommand.write(30); // bTimeOut2
		verifyCommand.write(0x80 | 0x08 | 0x00 | 0x01); // bmFormatString
		/*
		 * bmFormatString. bit 7: 1 = system units are bytes
		 * 
		 * bit 6-3: 1 = PIN position in APDU command after Lc, so just after the
		 * 0x20 | pinSize.
		 * 
		 * bit 2: 0 = left justify data
		 * 
		 * bit 1-0: 1 = BCD
		 */
		verifyCommand.write(0x47); // bmPINBlockString
		/*
		 * bmPINBlockString
		 * 
		 * bit 7-4: 4 = PIN length
		 * 
		 * bit 3-0: 7 = PIN block size (7 times 0xff)
		 */
		verifyCommand.write(0x04); // bmPINLengthFormat
		/*
		 * bmPINLengthFormat. weird... the values do not make any sense to me.
		 * 
		 * bit 7-5: 0 = RFU
		 * 
		 * bit 4: 0 = system units are bits
		 * 
		 * bit 3-0: 4 = PIN length position in APDU
		 */
		verifyCommand.write(new byte[] { (byte) MAX_PIN_SIZE,
				(byte) MIN_PIN_SIZE }); // wPINMaxExtraDigit
		/*
		 * first byte = maximum PIN size in digit
		 * 
		 * second byte = minimum PIN size in digit.
		 */
		verifyCommand.write(0x02); // bEntryValidationCondition
		/*
		 * 0x02 = validation key pressed. So the user must press the green
		 * button on his pinpad.
		 */
		verifyCommand.write(0x01); // bNumberMessage
		/*
		 * 0x01 = message with index in bMsgIndex
		 */
		verifyCommand.write(new byte[] { getLanguageId(), 0x04 }); // wLangId
		/*
		 * 0x04 = default sub-language
		 */
		verifyCommand.write(0x00); // bMsgIndex
		/*
		 * 0x00 = PIN insertion prompt
		 */
		verifyCommand.write(new byte[] { 0x00, 0x00, 0x00 }); // bTeoPrologue
		/*
		 * bTeoPrologue : only significant for T=1 protocol.
		 */
		byte[] verifyApdu = new byte[] {
				0x00, // CLA
				(byte) apduIns, // INS
				0x00, // P1
				0x01, // P2
				0x08, // Lc = 8 bytes in command data
				(byte) 0x20, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
		verifyCommand.write(verifyApdu.length & 0xff); // ulDataLength[0]
		verifyCommand.write(0x00); // ulDataLength[1]
		verifyCommand.write(0x00); // ulDataLength[2]
		verifyCommand.write(0x00); // ulDataLength[3]
		verifyCommand.write(verifyApdu); // abData
		byte[] verifyCommandData = verifyCommand.toByteArray();
		return verifyCommandData;
	}

	private byte getLanguageId() {
		/*
		 * USB language Ids
		 */
		if (Locale.FRENCH.equals(this.locale)) {
			return 0x0c;
		}
		if (Locale.GERMAN.equals(this.locale)) {
			return 0x07;
		}
		String language = this.locale.getLanguage();
		if ("nl".equals(language)) {
			return 0x13;
		}
		return 0x09; // ENGLISH
	}

	private byte[] createPINModificationDataStructure(int apduIns)
			throws IOException {
		ByteArrayOutputStream modifyCommand = new ByteArrayOutputStream();
		modifyCommand.write(30); // bTimeOut
		modifyCommand.write(30); // bTimeOut2
		modifyCommand.write(0x80 | 0x08 | 0x00 | 0x01); // bmFormatString
		/*
		 * bmFormatString. bit 7: 1 = system units are bytes
		 * 
		 * bit 6-3: 1 = PIN position in APDU command after Lc, so just after the
		 * 0x20 | pinSize.
		 * 
		 * bit 2: 0 = left justify data
		 * 
		 * bit 1-0: 1 = BCD
		 */

		modifyCommand.write(0x47); // bmPINBlockString
		/*
		 * bmPINBlockString
		 * 
		 * bit 7-4: 4 = PIN length
		 * 
		 * bit 3-0: 7 = PIN block size (7 times 0xff)
		 */

		modifyCommand.write(0x04); // bmPINLengthFormat
		/*
		 * bmPINLengthFormat. weird... the values do not make any sense to me.
		 * 
		 * bit 7-5: 0 = RFU
		 * 
		 * bit 4: 0 = system units are bits
		 * 
		 * bit 3-0: 4 = PIN length position in APDU
		 */

		modifyCommand.write(0x00); // bInsertionOffsetOld
		/*
		 * bInsertionOffsetOld: Insertion position offset in bytes for the
		 * current PIN
		 */

		modifyCommand.write(0x8); // bInsertionOffsetNew
		/*
		 * bInsertionOffsetNew: Insertion position offset in bytes for the new
		 * PIN
		 */

		modifyCommand.write(new byte[] { (byte) MAX_PIN_SIZE,
				(byte) MIN_PIN_SIZE }); // wPINMaxExtraDigit
		/*
		 * first byte = maximum PIN size in digit
		 * 
		 * second byte = minimum PIN size in digit.
		 */

		modifyCommand.write(0x03); // bConfirmPIN
		/*
		 * bConfirmPIN: Flags governing need for confirmation of new PIN
		 */

		modifyCommand.write(0x02); // bEntryValidationCondition
		/*
		 * 0x02 = validation key pressed. So the user must press the green
		 * button on his pinpad.
		 */

		modifyCommand.write(0x03); // bNumberMessage
		/*
		 * 0x03 = message with index in bMsgIndex
		 */

		modifyCommand.write(new byte[] { getLanguageId(), 0x04 }); // wLangId
		/*
		 * 0x04 = default sub-language
		 */

		modifyCommand.write(0x00); // bMsgIndex1
		/*
		 * 0x00 = PIN insertion prompt
		 */

		modifyCommand.write(0x01); // bMsgIndex2
		/*
		 * 0x01 = new PIN prompt
		 */

		modifyCommand.write(0x02); // bMsgIndex3
		/*
		 * 0x02 = new PIN again prompt
		 */

		modifyCommand.write(new byte[] { 0x00, 0x00, 0x00 }); // bTeoPrologue
		/*
		 * bTeoPrologue : only significant for T=1 protocol.
		 */

		byte[] modifyApdu = new byte[] {
				0x00, // CLA
				(byte) apduIns, // INS
				0x00, // P1
				0x01, // P2
				0x10, // Lc = 16 bytes in command data
				(byte) 0x20, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0x20, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
		modifyCommand.write(modifyApdu.length & 0xff); // ulDataLength[0]
		modifyCommand.write(0x00); // ulDataLength[1]
		modifyCommand.write(0x00); // ulDataLength[2]
		modifyCommand.write(0x00); // ulDataLength[3]
		modifyCommand.write(modifyApdu); // abData
		byte[] modifyCommandData = modifyCommand.toByteArray();
		return modifyCommandData;
	}

	private ResponseAPDU verifyPin(int retriesLeft) throws CardException {
		char[] pin = this.dialogs.getPin(retriesLeft);
		byte[] verifyData = new byte[] { (byte) (0x20 | pin.length),
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
		for (int idx = 0; idx < pin.length; idx += 2) {
			char digit1 = pin[idx];
			char digit2;
			if (idx + 1 < pin.length) {
				digit2 = pin[idx + 1];
			} else {
				digit2 = '0' + 0xf;
			}
			byte value = (byte) (byte) ((digit1 - '0' << 4) + (digit2 - '0'));
			verifyData[idx / 2 + 1] = value;
		}
		Arrays.fill(pin, (char) 0); // minimize exposure

		this.view.addDetailMessage("verifying PIN...");
		CommandAPDU verifyApdu = new CommandAPDU(0x00, 0x20, 0x00, 0x01,
				verifyData);
		try {
			ResponseAPDU responseApdu = transmit(verifyApdu);
			return responseApdu;
		} finally {
			Arrays.fill(verifyData, (byte) 0); // minimize exposure
		}
	}

	public byte[] signAuthn(byte[] toBeSigned, boolean requireSecureReader)
			throws NoSuchAlgorithmException, CardException, IOException,
			InterruptedException {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
		byte[] digest = messageDigest.digest(toBeSigned);
		byte keyId = (byte) 0x82; // authentication key

		byte[] signatureValue = sign(digest, "SHA-1", keyId,
				requireSecureReader);
		return signatureValue;
	}

	public void changePin(boolean requireSecureReader) throws Exception {
		Integer directPinModifyFeature = getFeature(FEATURE_MODIFY_PIN_DIRECT_TAG);
		Integer modifyPinStartFeature = getFeature(FEATURE_MODIFY_PIN_START_TAG);

		if (requireSecureReader && null == directPinModifyFeature
				&& null == modifyPinStartFeature) {
			throw new SecurityException("not a secure reader");
		}

		int retriesLeft = -1;
		ResponseAPDU responseApdu;
		do {
			if (null != modifyPinStartFeature) {
				this.view.addDetailMessage("using modify pin start/finish...");
				responseApdu = doChangePinStartFinish(retriesLeft,
						modifyPinStartFeature);
			} else if (null != directPinModifyFeature) {
				this.view
						.addDetailMessage("could use direct PIN modify here...");
				responseApdu = doChangePinDirect(retriesLeft,
						directPinModifyFeature);
			} else {
				responseApdu = doChangePin(retriesLeft);
			}

			if (0x9000 != responseApdu.getSW()) {
				this.view.addDetailMessage("CHANGE PIN error");
				this.view.addDetailMessage("SW: "
						+ Integer.toHexString(responseApdu.getSW()));
				if (0x6983 == responseApdu.getSW()) {
					this.dialogs.showPinBlockedDialog();
					throw new RuntimeException("eID card blocked!");
				}
				if (0x63 != responseApdu.getSW1()) {
					this.view
							.addDetailMessage("PIN change error. Card blocked?");
					throw new RuntimeException("PIN change error.");
				}
				retriesLeft = responseApdu.getSW2() & 0xf;
				this.view.addDetailMessage("retries left: " + retriesLeft);
			}
		} while (0x9000 != responseApdu.getSW());
		this.dialogs.showPinChanged();
	}

	private ResponseAPDU doChangePinStartFinish(int retriesLeft,
			Integer modifyPinStartFeature) throws IOException, CardException,
			InterruptedException {
		byte[] modifyCommandData = createPINModificationDataStructure(0x24);
		this.card.transmitControlCommand(modifyPinStartFeature,
				modifyCommandData);
		int getKeyPressedFeature = getFeature(FEATURE_GET_KEY_PRESSED_TAG);

		try {
			this.view.addDetailMessage("enter old PIN...");
			this.dialogs.showPINModifyOldPINFrame(retriesLeft);
			ccidWaitForOK(getKeyPressedFeature);
			this.dialogs.disposePINPadFrame();

			this.dialogs.showPINModifyNewPINFrame(retriesLeft);
			this.view.addDetailMessage("enter new PIN...");
			ccidWaitForOK(getKeyPressedFeature);
			this.dialogs.disposePINPadFrame();

			this.dialogs.showPINModifyNewPINAgainFrame(retriesLeft);
			this.view.addDetailMessage("enter new PIN again...");
			ccidWaitForOK(getKeyPressedFeature);
		} finally {
			this.dialogs.disposePINPadFrame();
		}

		int modifyPinFinishIoctl = getFeature(FEATURE_MODIFY_PIN_FINISH_TAG);
		byte[] modifyPinFinishResult = this.card.transmitControlCommand(
				modifyPinFinishIoctl, new byte[0]);
		ResponseAPDU responseApdu = new ResponseAPDU(modifyPinFinishResult);
		return responseApdu;
	}

	private void ccidWaitForOK(int getKeyPressedFeature) throws CardException,
			InterruptedException {
		// wait for key pressed
		loop: while (true) {
			byte[] getKeyPressedResult = this.card.transmitControlCommand(
					getKeyPressedFeature, new byte[0]);
			byte key = getKeyPressedResult[0];
			switch (key) {
			case 0x00:
				// this.view.addDetailMessage("waiting for CCID...");
				Thread.sleep(200);
				break;
			case 0x2b:
				this.view.addDetailMessage("PIN digit");
				break;
			case 0x0a:
				this.view.addDetailMessage("erase PIN digit");
				break;
			case 0x0d:
				this.view.addDetailMessage("user confirmed");
				break loop;
			case 0x1b:
				this.view.addDetailMessage("user canceled");
				// XXX: need to send the PIN finish ioctl?
				throw new SecurityException("canceled by user");
			case 0x40:
				// happens in case of a reader timeout
				this.view.addDetailMessage("PIN abort");
				break loop;
			default:
				this.view.addDetailMessage("CCID get key pressed result: "
						+ key + " hex: " + Integer.toHexString(key));
			}
		}
	}

	private ResponseAPDU doChangePinDirect(int retriesLeft,
			Integer directPinModifyFeature) throws IOException, CardException {
		this.view.addDetailMessage("direct PIN modification...");
		byte[] modifyCommandData = createPINModificationDataStructure(0x24);
		this.dialogs.showPINChangePadFrame(retriesLeft);
		byte[] result;
		try {
			result = this.card.transmitControlCommand(directPinModifyFeature,
					modifyCommandData);
		} finally {
			this.dialogs.disposePINPadFrame();
		}
		ResponseAPDU responseApdu = new ResponseAPDU(result);
		if (0x6402 == responseApdu.getSW()) {
			this.view.addDetailMessage("PINs differ");
		} else if (0x6401 == responseApdu.getSW()) {
			this.view.addDetailMessage("canceled by user");
			throw new SecurityException("canceled by user");
		} else if (0x6400 == responseApdu.getSW()) {
			this.view.addDetailMessage("PIN pad timeout");
		}
		return responseApdu;
	}

	private ResponseAPDU doChangePin(int retriesLeft) throws CardException {
		Pins pins = this.dialogs.getPins(retriesLeft);
		char[] oldPin = pins.getOldPin();
		char[] newPin = pins.getNewPin();

		byte[] changePinData = new byte[] { (byte) (0x20 | oldPin.length),
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) (0x20 | newPin.length), (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };

		for (int idx = 0; idx < oldPin.length; idx += 2) {
			char digit1 = oldPin[idx];
			char digit2;
			if (idx + 1 < oldPin.length) {
				digit2 = oldPin[idx + 1];
			} else {
				digit2 = '0' + 0xf;
			}
			byte value = (byte) (byte) ((digit1 - '0' << 4) + (digit2 - '0'));
			changePinData[idx / 2 + 1] = value;
		}
		Arrays.fill(oldPin, (char) 0); // minimize exposure

		for (int idx = 0; idx < newPin.length; idx += 2) {
			char digit1 = newPin[idx];
			char digit2;
			if (idx + 1 < newPin.length) {
				digit2 = newPin[idx + 1];
			} else {
				digit2 = '0' + 0xf;
			}
			byte value = (byte) (byte) ((digit1 - '0' << 4) + (digit2 - '0'));
			changePinData[(idx / 2 + 1) + 8] = value;
		}
		Arrays.fill(newPin, (char) 0); // minimize exposure

		CommandAPDU changePinApdu = new CommandAPDU(0x00, 0x24, // change
				// reference
				// data
				0x00, // user password change
				0x01, changePinData);
		try {
			ResponseAPDU responseApdu = transmit(changePinApdu);
			return responseApdu;
		} finally {
			Arrays.fill(changePinData, (byte) 0);
		}
	}

	public void unblockPin(boolean requireSecureReader) throws Exception {
		Integer directPinVerifyFeature = getFeature(FEATURE_VERIFY_PIN_DIRECT_TAG);

		if (requireSecureReader && null == directPinVerifyFeature) {
			throw new SecurityException("not a secure reader");
		}

		ResponseAPDU responseApdu;
		int retriesLeft = -1;
		do {
			if (null != directPinVerifyFeature) {
				this.view
						.addDetailMessage("could use direct PIN verify here...");
				responseApdu = verifyPukDirect(retriesLeft,
						directPinVerifyFeature);
			} else {
				responseApdu = doUnblockPin(retriesLeft);
			}

			if (0x9000 != responseApdu.getSW()) {
				this.view.addDetailMessage("PIN unblock error");
				this.view.addDetailMessage("SW: "
						+ Integer.toHexString(responseApdu.getSW()));
				if (0x6983 == responseApdu.getSW()) {
					this.dialogs.showPinBlockedDialog();
					throw new RuntimeException("eID card blocked!");
				}
				if (0x63 != responseApdu.getSW1()) {
					this.view.addDetailMessage("PIN unblock error.");
					throw new RuntimeException("PIN unblock error.");
				}
				retriesLeft = responseApdu.getSW2() & 0xf;
				this.view.addDetailMessage("retries left: " + retriesLeft);
			}
		} while (0x9000 != responseApdu.getSW());
		this.dialogs.showPinUnblocked();
	}

	private ResponseAPDU doUnblockPin(int retriesLeft) throws CardException {
		char[] puk1 = new char[PUK_SIZE];
		char[] puk2 = new char[PUK_SIZE];
		this.dialogs.getPuks(retriesLeft, puk1, puk2);

		char[] fullPuk = new char[2 * PUK_SIZE];
		System.arraycopy(puk2, 0, fullPuk, 0, PUK_SIZE);
		Arrays.fill(puk2, (char) 0);
		System.arraycopy(puk1, 0, fullPuk, PUK_SIZE, PUK_SIZE);
		Arrays.fill(puk1, (char) 0);

		byte[] unblockPinData = new byte[] { 0x20 | (PUK_SIZE + PUK_SIZE),
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF };

		for (int idx = 0; idx < fullPuk.length; idx += 2) {
			char digit1 = fullPuk[idx];
			char digit2 = fullPuk[idx + 1];
			byte value = (byte) (byte) ((digit1 - '0' << 4) + (digit2 - '0'));
			unblockPinData[idx / 2 + 1] = value;
		}
		Arrays.fill(fullPuk, (char) 0); // minimize exposure

		CommandAPDU changePinApdu = new CommandAPDU(0x00, 0x2C, 0x00, 0x01,
				unblockPinData);
		try {
			ResponseAPDU responseApdu = transmit(changePinApdu);
			return responseApdu;
		} finally {
			Arrays.fill(unblockPinData, (byte) 0);
		}
	}

	public List<X509Certificate> getSignCertificateChain()
			throws CardException, IOException, CertificateException {
		List<X509Certificate> signCertificateChain = new LinkedList<X509Certificate>();
		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");

		this.view.addDetailMessage("reading sign certificate...");
		byte[] signCertFile = readFile(SIGN_CERT_FILE_ID);
		X509Certificate signCert = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(signCertFile));
		signCertificateChain.add(signCert);

		this.view.addDetailMessage("reading Citizen CA certificate...");
		byte[] citizenCaCertFile = readFile(CA_CERT_FILE_ID);
		X509Certificate citizenCaCert = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(citizenCaCertFile));
		signCertificateChain.add(citizenCaCert);

		this.view.addDetailMessage("reading Root CA certificate...");
		byte[] rootCaCertFile = readFile(ROOT_CERT_FILE_ID);
		X509Certificate rootCaCert = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(rootCaCertFile));
		signCertificateChain.add(rootCaCert);

		return signCertificateChain;
	}

	public byte[] sign(byte[] digestValue, String digestAlgo,
			boolean requireSecureReader) throws NoSuchAlgorithmException,
			CardException, IOException, InterruptedException {
		byte keyId = (byte) 0x83; // non-repudiation key
		byte[] signatureValue = sign(digestValue, digestAlgo, keyId,
				requireSecureReader);
		return signatureValue;
	}

	public void logoff() throws Exception {
		CommandAPDU logoffApdu = new CommandAPDU(0x80, 0xE6, 0x00, 0x00);
		this.view.addDetailMessage("logoff...");
		ResponseAPDU responseApdu = transmit(logoffApdu);
		if (0x9000 != responseApdu.getSW()) {
			throw new RuntimeException("logoff failed");
		}
	}

	public void logoff(String readerName) throws Exception {
		this.view
				.addDetailMessage("logoff from reader: \"" + readerName + "\"");
		TerminalFactory factory = TerminalFactory.getDefault();
		CardTerminals cardTerminals = factory.terminals();
		CardTerminal cardTerminal = cardTerminals.getTerminal(readerName);
		if (null == cardTerminal) {
			this.view.addDetailMessage("logoff: card reader not found: "
					+ readerName);
			List<String> readerList = getReaderList();
			this.view.addDetailMessage("reader list: " + readerList);
			// throw new RuntimeException("card reader not found: " +
			// readerName);
			// we won't fail in this case...
			return;
		}
		Card card = cardTerminal.connect("T=0");
		try {
			CardChannel cardChannel = card.getBasicChannel();
			CommandAPDU logoffApdu = new CommandAPDU(0x80, 0xE6, 0x00, 0x00);
			ResponseAPDU responseApdu = cardChannel.transmit(logoffApdu);
			this.view.addDetailMessage("logoff...");
			if (0x9000 != responseApdu.getSW()) {
				throw new RuntimeException("logoff failed");
			}
		} finally {
			card.disconnect(true);
		}
	}

	private ResponseAPDU transmit(CommandAPDU commandApdu) throws CardException {
		ResponseAPDU responseApdu = this.cardChannel.transmit(commandApdu);
		if (0x6c == responseApdu.getSW1()) {
			/*
			 * A minimum delay of 10 msec between the answer ‘6C xx’ and the
			 * next APDU is mandatory for eID v1.0 and v1.1 cards.
			 */
			this.view.addDetailMessage("sleeping...");
			try {
				Thread.sleep(10);
			} catch (InterruptedException e) {
				throw new RuntimeException("cannot sleep");
			}
			responseApdu = this.cardChannel.transmit(commandApdu);
		}
		return responseApdu;
	}

	public void selectBelpicJavaCardApplet() {
		CommandAPDU selectApplicationApdu = new CommandAPDU(0x00, 0xA4, 0x04,
				0x0C, BELPIC_AID);
		ResponseAPDU responseApdu;
		try {
			responseApdu = transmit(selectApplicationApdu);
		} catch (CardException e) {
			this.view.addDetailMessage("error selecting BELPIC");
			return;
		}
		if (0x9000 != responseApdu.getSW()) {
			this.view.addDetailMessage("could not select BELPIC");
			this.view.addDetailMessage("status word: "
					+ Integer.toHexString(responseApdu.getSW()));
			/*
			 * Try to select the Applet.
			 */
			selectApplicationApdu = new CommandAPDU(0x00, 0xA4, 0x04, 0x00,
					APPLET_AID);
			try {
				responseApdu = transmit(selectApplicationApdu);
			} catch (CardException e) {
				this.view.addDetailMessage("error selecting Applet");
				return;
			}
			if (0x9000 != responseApdu.getSW()) {
				this.view.addDetailMessage("could not select applet");
			} else {
				this.view.addDetailMessage("BELPIC JavaCard applet selected");
			}
		} else {
			this.view.addDetailMessage("BELPIC JavaCard applet selected");
		}
	}

	public byte[] signAuthn(byte[] toBeSigned) throws NoSuchAlgorithmException,
			CardException, IOException, InterruptedException {
		return signAuthn(toBeSigned, false);
	}

	public byte[] sign(byte[] digestValue, String digestAlgo)
			throws NoSuchAlgorithmException, CardException, IOException,
			InterruptedException {
		return sign(digestValue, digestAlgo, false);
	}

	public void changePin() throws Exception {
		changePin(false);
	}

	public void unblockPin() throws Exception {
		unblockPin(false);
	}

	public X509Certificate diagnosticTests(
			DiagnosticCallbackHandler diagnosticCallbackHandler) {
		this.view.addDetailMessage("start diagnostic tests");
		this.view.setStatusMessage(Status.NORMAL, MESSAGE_ID.DIAGNOSTIC_MODE);
		/*
		 * PC/SC tests
		 */
		if ("None".equals(this.terminalFactory.getType())) {
			diagnosticCallbackHandler.addTestResult(DiagnosticTests.PCSC,
					false, "PC/SC service not available");
			return null;
		}
		diagnosticCallbackHandler.addTestResult(DiagnosticTests.PCSC, true,
				terminalFactory.getType());

		/*
		 * CARD READER tests
		 */
		if (false == hasCardReader()) {
			this.view
					.setStatusMessage(Status.NORMAL, MESSAGE_ID.CONNECT_READER);
			waitForCardReader();
		}

		try {
			if (false == isEidPresent()) {
				this.view.setStatusMessage(Status.NORMAL,
						MESSAGE_ID.INSERT_CARD_QUESTION);
				waitForEidPresent();
			}
		} catch (Exception e) {
			diagnosticCallbackHandler.addTestResult(
					DiagnosticTests.CARD_READER, false, e.getMessage());
			return null;
		}

		this.view.setStatusMessage(Status.NORMAL, MESSAGE_ID.DIAGNOSTIC_MODE);

		Integer directPinVerifyFeature = getFeature(FEATURE_VERIFY_PIN_DIRECT_TAG);
		Integer verifyPinStartFeature = getFeature(FEATURE_VERIFY_PIN_START_TAG);

		String terminalName = this.cardTerminal.getName();
		String cardReaderInformation = terminalName;
		if (null != directPinVerifyFeature || null != verifyPinStartFeature) {
			cardReaderInformation += " (CCID secure pinpad reader)";
		}
		diagnosticCallbackHandler.addTestResult(DiagnosticTests.CARD_READER,
				true, cardReaderInformation);

		/*
		 * eID Readout tests.
		 */
		CertificateFactory certificateFactory;
		try {
			certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			this.view.addTestResult(DiagnosticTests.EID_READOUT, false,
					e.getMessage());
			return null;
		}
		int maxProgress = 1; // identity file
		maxProgress++; // address file
		maxProgress += 3000 / 255; // photo
		maxProgress++; // identity signature file
		maxProgress++; // address signature file
		maxProgress += (1050 / 255) + 1; // authn cert file
		maxProgress += (1050 / 255) + 1; // sign cert file
		maxProgress += (1050 / 255) + 1; // citizen CA cert file
		maxProgress += (1050 / 255) + 1; // root CA cert file
		maxProgress += (1050 / 255) + 1; // NRN CA cert file
		this.view.resetProgress(maxProgress);
		try {
			readFile(IDENTITY_FILE_ID);
		} catch (Exception e) {
			diagnosticCallbackHandler.addTestResult(
					DiagnosticTests.EID_READOUT, false, "Identity file");
			return null;
		}
		try {
			readFile(ADDRESS_FILE_ID);
		} catch (Exception e) {
			diagnosticCallbackHandler.addTestResult(
					DiagnosticTests.EID_READOUT, false, "Address file");
			return null;
		}
		try {
			readFile(PHOTO_FILE_ID);
		} catch (Exception e) {
			diagnosticCallbackHandler.addTestResult(
					DiagnosticTests.EID_READOUT, false, "Photo file");
			return null;
		}
		try {
			readFile(IDENTITY_SIGN_FILE_ID);
		} catch (Exception e) {
			diagnosticCallbackHandler.addTestResult(
					DiagnosticTests.EID_READOUT, false,
					"Identity signature file");
			return null;
		}
		try {
			readFile(ADDRESS_SIGN_FILE_ID);
		} catch (Exception e) {
			diagnosticCallbackHandler.addTestResult(
					DiagnosticTests.EID_READOUT, false,
					"Address signature file");
			return null;
		}
		X509Certificate authnCertificate;
		try {
			byte[] certData = readFile(AUTHN_CERT_FILE_ID);
			authnCertificate = (X509Certificate) certificateFactory
					.generateCertificate(new ByteArrayInputStream(certData));
		} catch (Exception e) {
			diagnosticCallbackHandler.addTestResult(
					DiagnosticTests.EID_READOUT, false,
					"Authentication certificate file");
			return null;
		}
		try {
			byte[] certData = readFile(SIGN_CERT_FILE_ID);
			certificateFactory.generateCertificate(new ByteArrayInputStream(
					certData));
		} catch (Exception e) {
			diagnosticCallbackHandler.addTestResult(
					DiagnosticTests.EID_READOUT, false,
					"Signature certificate file");
			return authnCertificate;
		}
		try {
			byte[] certData = readFile(CA_CERT_FILE_ID);
			certificateFactory.generateCertificate(new ByteArrayInputStream(
					certData));
		} catch (Exception e) {
			diagnosticCallbackHandler.addTestResult(
					DiagnosticTests.EID_READOUT, false,
					"Citizen CA certificate file");
			return authnCertificate;
		}
		try {
			byte[] certData = readFile(ROOT_CERT_FILE_ID);
			certificateFactory.generateCertificate(new ByteArrayInputStream(
					certData));
		} catch (Exception e) {
			diagnosticCallbackHandler.addTestResult(
					DiagnosticTests.EID_READOUT, false,
					"Root CA certificate file");
			return authnCertificate;
		}
		try {
			byte[] certData = readFile(RRN_CERT_FILE_ID);
			certificateFactory.generateCertificate(new ByteArrayInputStream(
					certData));
		} catch (Exception e) {
			diagnosticCallbackHandler.addTestResult(
					DiagnosticTests.EID_READOUT, false, "NRN certificate file");
			return authnCertificate;
		}
		diagnosticCallbackHandler.addTestResult(DiagnosticTests.EID_READOUT,
				true, null);
		this.view.setProgressIndeterminate();

		/*
		 * eID crypto tests.
		 */
		CommandAPDU getChallengeApdu = new CommandAPDU(0x00, 0x84, 0x00, 0x00,
				new byte[] {}, 0, 0, 20);
		ResponseAPDU responseApdu;
		try {
			responseApdu = transmit(getChallengeApdu);
		} catch (CardException e) {
			diagnosticCallbackHandler.addTestResult(DiagnosticTests.EID_CRYPTO,
					false, e.getMessage());
			return authnCertificate;
		}
		if (0x9000 != responseApdu.getSW()) {
			diagnosticCallbackHandler.addTestResult(DiagnosticTests.EID_CRYPTO,
					false, "Challenge error");
			return authnCertificate;
		}
		byte[] challenge = responseApdu.getData();

		ByteArrayOutputStream internalAuthnData = new ByteArrayOutputStream();
		internalAuthnData.write(0x94);
		internalAuthnData.write(0x14);
		try {
			internalAuthnData.write(challenge);
		} catch (IOException e) {
			diagnosticCallbackHandler.addTestResult(DiagnosticTests.EID_CRYPTO,
					false, e.getMessage());
			return authnCertificate;
		}
		CommandAPDU internalAuthnApdu = new CommandAPDU(0x00, 0x88, 0x02, 0x81,
				internalAuthnData.toByteArray());
		try {
			responseApdu = transmit(internalAuthnApdu);
		} catch (CardException e) {
			diagnosticCallbackHandler.addTestResult(DiagnosticTests.EID_CRYPTO,
					false, e.getMessage());
			return authnCertificate;
		}
		if (0x9000 != responseApdu.getSW()) {
			diagnosticCallbackHandler.addTestResult(DiagnosticTests.EID_CRYPTO,
					false, "Internal authentication failed");
			return authnCertificate;
		}
		diagnosticCallbackHandler.addTestResult(DiagnosticTests.EID_CRYPTO,
				true, null);
		return authnCertificate;
	}
}
