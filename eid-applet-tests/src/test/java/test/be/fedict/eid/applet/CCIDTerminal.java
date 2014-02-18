package test.be.fedict.eid.applet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.beblue.jna.usb.LibUSB;
import org.beblue.jna.usb.usb_dev_handle;
import org.beblue.jna.usb.usb_device;
import org.beblue.jna.usb.usb_endpoint_descriptor;
import org.beblue.jna.usb.usb_interface_descriptor;

public class CCIDTerminal {

	static final Log LOG = LogFactory.getLog(CCIDTerminal.class);

	private usb_device usbDevice;
	private usb_interface_descriptor usbInterfaceDescriptor;
	private usb_dev_handle usbDevHandle;
	private byte endPointBulkIn;
	private byte endPointBulkOut;
	private byte endPointInterrupt;
	private int busNumber;
	private int deviceNumber;
	private byte sequenceNumber = 0;

	public CCIDTerminal(usb_device usbDevice,
			usb_interface_descriptor usbInterfaceDescriptor) {
		this.usbDevice = usbDevice;
		this.usbInterfaceDescriptor = usbInterfaceDescriptor;
		this.setEndPoints();
		usbDevHandle = null;
	}

	public usb_device getUsbDevice() {
		return usbDevice;
	}

	public usb_interface_descriptor getUsbInterfaceDescriptor() {
		return usbInterfaceDescriptor;
	}

	public void setBusNumber(int busNumber) {
		this.busNumber = busNumber;
	}

	public void setDeviceNumber(int deviceNumber) {
		this.deviceNumber = deviceNumber;
	}

	public byte getEndPointBulkIn() {
		return this.endPointBulkIn;
	}

	public byte getEndPointBulkOut() {
		return this.endPointBulkOut;
	}

	public byte getEndPointInterrupt() {
		return this.endPointInterrupt;
	}

	private void setEndPoints() {
		usb_endpoint_descriptor[] usbEndPointDescriptors = (usb_endpoint_descriptor[]) usbInterfaceDescriptor.endpoint
				.toArray(usbInterfaceDescriptor.bNumEndpoints);
		for (int i = 0; i < usbEndPointDescriptors.length; i++) {
			if ((usbEndPointDescriptors[i].bmAttributes & 3) == 3) // Interrupt
				endPointInterrupt = usbEndPointDescriptors[i].bEndpointAddress;
			if ((usbEndPointDescriptors[i].bmAttributes & 3) == 2) // Bulk
				if ((usbEndPointDescriptors[i].bEndpointAddress & 0x80) == 0x80) // Bulk
																					// IN
					endPointBulkIn = usbEndPointDescriptors[i].bEndpointAddress;
				else
					// Bulk OUT
					endPointBulkOut = usbEndPointDescriptors[i].bEndpointAddress;
		}
	}

	public void open() {
		int rv;
		if (usbDevHandle == null)
			usbDevHandle = LibUSB.libUSB.usb_open(usbDevice);
		if (usbDevHandle == null) {
			LOG.debug(String.format("usb_open device failed (%d/%d)",
					busNumber, deviceNumber));
			throw new RuntimeException(String.format(
					"usb_open device failed (%d/%d)", busNumber, deviceNumber));
		}
		rv = LibUSB.libUSB.usb_set_configuration(usbDevHandle, 1);
		if (rv != 0) {
			LOG.debug(String.format("set configuration failed (%d/%d): %d",
					busNumber, deviceNumber, rv));
			throw new RuntimeException(String.format(
					"set configuration failed (%d/%d): %d", busNumber,
					deviceNumber, rv));
		}
		/*
		 * rv = LibUSB.libUSB.usb_set_altinterface(usbDevHandle,
		 * usbInterfaceDescriptor.bAlternateSetting); if (rv != 0) {
		 * LOG.debug(String
		 * .format("set alternative interface failed (%d/%d): %d",
		 * busNumber,deviceNumber,rv)); throw new
		 * RuntimeException(String.format(
		 * "set alternative interface failed (%d/%d): %d",
		 * busNumber,deviceNumber,rv)); }
		 */
		rv = LibUSB.libUSB.usb_claim_interface(usbDevHandle,
				usbInterfaceDescriptor.bInterfaceNumber);
		if (rv != 0) {
			LOG.debug(String.format("claim interface failed (%d/%d): %d",
					busNumber, deviceNumber, rv));
			throw new RuntimeException(String.format(
					"claim interface failed (%d/%d): %d", busNumber,
					deviceNumber, rv));
		}
	}

	public void close() {
		if (usbDevHandle != null)
			LibUSB.libUSB.usb_close(usbDevHandle);
	}

	// read from BulkIn Endpoint
	public byte[] read() {
		byte[] buffer = new byte[256];
		int rv = LibUSB.libUSB.usb_bulk_read(usbDevHandle, endPointBulkIn,
				buffer, buffer.length, 5000); // timeout: 5 secs
		if (rv < 0) {
			LOG.debug(String.format("read failed (%d/%d): %d", busNumber,
					deviceNumber, rv & 0xFF));
			throw new RuntimeException("read failed");
		}
		return buffer;
	}

	// write to BulkOut Endpoint
	public void write(byte[] buffer) {
		int rv = LibUSB.libUSB.usb_bulk_write(usbDevHandle, endPointBulkOut,
				buffer, buffer.length, 5000); // timeout: 5 secs
		if (rv < 0) {
			LOG.debug(String.format("write failed (%d/%d): %d", busNumber,
					deviceNumber, rv & 0xFF));
			throw new RuntimeException("write failed");
		}
		LOG.debug(String.format("write. Buffer: %s", bytesToString(buffer)));

	}

	// send xfrblock command to card
	public void transmit(byte[] data) {
		byte[] cmd = new byte[10 + data.length];
		byte seq = this.sequenceNumber++;
		cmd[0] = 0x6F; /* XfrBlock */
		cmd[1] = (byte) (data.length & 0xFF);
		cmd[2] = (byte) ((data.length << 8) & 0xFF);
		cmd[3] = (byte) ((data.length << 16) & 0xFF);
		cmd[4] = (byte) ((data.length << 24) & 0xFF); /* dwLength */
		cmd[5] = 0; // /* slot number */
		cmd[6] = seq; // sequence number
		cmd[7] = 0; // Extended block waiting timeout
		cmd[8] = cmd[9] = 0; /* expected length */
		for (int i = 0; i < data.length; i++) {
			cmd[10 + i] = data[i];
		}
		this.write(cmd);
		LOG.debug(String.format("transmit. Answer: %s", bytesToString(cmd)));
	}

	public byte[] receive() {
		byte[] answer;
		do {
			answer = this.read();
			if ((answer[7] & (byte) 0x40) == (byte) 0x40) { // 01 0000 00
															// bmCommandStatus
															// 1: Error
				LOG.debug(String.format("receive failed (%d/%d): %x",
						busNumber, deviceNumber, answer[8]));
				throw new RuntimeException(String.format(
						"receive failed (%d/%d): %x", busNumber, deviceNumber,
						answer[8]));
			}
			if ((answer[7] & (byte) 0x80) == (byte) 0x80)
				;
			{ // 10 0000 00 bmCommandStatus 1: Time extension requested
				LOG.debug(String.format(
						"receive: time extension requested (%d/%d)", busNumber,
						deviceNumber));
			}
		} while ((answer[7] & (byte) 0x80) == (byte) 0x80);
		LOG.debug(String.format("receive. Answer: %s", bytesToString(answer)));
		int datalength = (answer[1] & 0xFF) + ((answer[2] & 0xFF) << 8)
				+ ((answer[3] & 0xFF) << 16) + ((answer[4] & 0xFF) << 24);
		byte[] data = new byte[datalength];
		for (int i = 0; i < datalength; i++) {
			data[i] = answer[10 + i];
		}
		return data;
	}

	// command to power on the card
	// returns ATR
	public byte[] powerOn() throws Exception {
		byte[] cmd = new byte[10];
		byte seq = this.sequenceNumber++;
		cmd[0] = 0x62; /* IccPowerOn */
		cmd[1] = cmd[2] = cmd[3] = cmd[4] = 0; /* dwLength */
		cmd[5] = 0; // slot number */
		cmd[6] = seq; // sequence number
		cmd[7] = 1; // 5V
		cmd[8] = cmd[9] = 0; /* RFU */
		this.write(cmd);
		return this.receive();
	}

	public byte[] powerOff() throws Exception {
		byte[] cmd = new byte[10];
		cmd[0] = 0x63; /* IccPowerOff */
		cmd[1] = cmd[2] = cmd[3] = cmd[4] = 0; /* dwLength */
		cmd[5] = 0; // ccid_descriptor->bCurrentSlotIndex; /* slot number */
		cmd[6] = this.sequenceNumber++; // sequence number
		cmd[7] = 1; // 5V
		cmd[8] = cmd[9] = 0; /* RFU */
		this.write(cmd);
		return this.receive();
	}

	public byte[] getSlotStatus() throws Exception {
		byte[] cmd = new byte[10];
		byte seq = this.sequenceNumber++;
		cmd[0] = 0x65; /* GetSlotStatus */
		cmd[1] = cmd[2] = cmd[3] = cmd[4] = 0; /* dwLength */
		cmd[5] = 0; // slot number */
		cmd[6] = seq; // sequence number
		cmd[7] = 0; // 5V
		cmd[8] = cmd[9] = 0; /* RFU */
		this.write(cmd);
		return this.receive();
	}

	private String bytesToString(byte[] data) {
		String dataString = "";
		for (int j = 0; j < data.length; j++)
			dataString += String.format("%2x ", data[j]);
		return dataString;
	}
}
