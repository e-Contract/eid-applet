package test.be.fedict.eid.applet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.lang.*;
import org.beblue.jna.usb.*;
import org.junit.Test;
import java.util.*;

/**
 * Tests for libUSB eID access
 * 
 * @author Koen De Causmaecker
 * 
 */
public class LibUSBTest {
	static final Log LOG = LogFactory.getLog(LibUSBTest.class);
	private ArrayList<CCIDTerminal> listCCIDTerminals() throws Exception {
		LibUSB.libUSB.usb_init();
		LibUSB.libUSB.usb_find_busses();
		LibUSB.libUSB.usb_find_devices();
		usb_bus usbBus = LibUSB.libUSB.usb_get_busses();
		ArrayList<CCIDTerminal> al = new ArrayList<CCIDTerminal>();
		while (usbBus != null) {
			usb_device usbDevice = usbBus.devices;
			while (usbDevice != null) {
				usb_config_descriptor[] usbConfigDescriptors = (usb_config_descriptor[]) usbDevice.config.toArray(usbDevice.descriptor.bNumConfigurations);
				for (int i = 0; i < usbConfigDescriptors.length;i++) {
					usb_interface[] usbInterfaces = (usb_interface[])usbConfigDescriptors[i].interf.toArray(usbConfigDescriptors[i].bNumInterfaces);
					for (int j = 0; j < usbInterfaces.length; j++) {
						usb_interface_descriptor[] usbInterfaceDescriptors = (usb_interface_descriptor[])
										usbInterfaces[j].altsetting.toArray(usbInterfaces[j].num_altsetting);
						for (int k = 0; k < usbInterfaceDescriptors.length; k++) {							
							if (usbInterfaceDescriptors[k].bInterfaceClass == 11) {
								CCIDTerminal t = new CCIDTerminal(usbDevice, usbInterfaceDescriptors[k]);
								
								t.setBusNumber(usbBus.location);
								t.setDeviceNumber(usbDevice.devnum);
								al.add(t);
							}
						}
					}
					usbDevice = usbDevice.next;
				}
			}
			usbBus = usbBus.next;
		}
		return al;
	}
	@Test
	public void testListReaders() throws Exception {
		ArrayList<CCIDTerminal> ccidTerminals = listCCIDTerminals();
		for (int i = 0; i < ccidTerminals.size();i++) {
			LOG.debug(String.format("Card terminal found. Vendor: 0x%x Product: 0x%x", 
				ccidTerminals.get(i).getUsbDevice().descriptor.idProduct, ccidTerminals.get(i).getUsbDevice().descriptor.idVendor));

		}
		//	usb_dev_handle usbDevHandle = LibUSB.libUSB.usb_open(usbDevice);
		//		int retval = LibUSB.libUSB.usb_set_configuration(usbDevHandle, i);
	}
	@Test 
	public void testPowerOn() throws Exception {
		ArrayList<CCIDTerminal> ccidTerminals = listCCIDTerminals();
		for (int i = 0; i < ccidTerminals.size();i++) {
			CCIDTerminal ct = ccidTerminals.get(i);
			ct.open();
			ct.powerOff();
			byte[] answer = ct.powerOn();
			LOG.debug(String.format("Card terminal powered on. ATR: %s", bytesToString(answer)));
			ct.close();
		}
	}
	@Test 
	public void testSelectIdentityFile() throws Exception {
		ArrayList<CCIDTerminal> ccidTerminals = listCCIDTerminals();
		
		byte[] apdu = {0x00, (byte)0xA4, 0x08, 0x0C, 0x06, 
				0x3F, 0x00,	(byte) 0xDF, 0x01, 0x40, 0x31}; // Identity File
		//00 A4 02 0C 02 3F 00 DF 01 40 31
		for (int i = 0; i < ccidTerminals.size();i++) {
			CCIDTerminal ct = ccidTerminals.get(i);
			ct.open();
			ct.powerOff();
			ct.powerOn();
			ct.transmit(apdu);
			byte [] answer = ct.receive();
			LOG.debug(String.format("SELECT Identity file sent. Answer: %s", bytesToString(answer)));
			ct.close();
		}
	}
	@Test 
	public void testReadIdentity() throws Exception {
		ArrayList<CCIDTerminal> ccidTerminals = listCCIDTerminals();
		
		byte[] apduSelectIdentity = {0x00, (byte)0xA4, 0x08, 0x0C, 0x06, 
				0x3F, 0x00,	(byte) 0xDF, 0x01, 0x40, 0x31}; // Identity File
		byte[] apduReadBinary = { 0x00, (byte)0xB0, 0, 0, (byte)0x80};

		for (int i = 0; i < ccidTerminals.size();i++) {
			byte [] answer;
			apduReadBinary[4] = (byte)0x80;
			CCIDTerminal ct = ccidTerminals.get(i);
			ct.open();
			ct.getSlotStatus();
			answer = ct.powerOn();
			LOG.debug(String.format("PowerOn. Answer: %s", bytesToString(answer)));

			do {
				ct.transmit(apduSelectIdentity);
				answer = ct.receive();
				LOG.debug(String.format("SELECT Identity file sent. Answer: %s", bytesToString(answer)));
	
				if (!(answer[0]==(byte)0x90 && answer[1]==0x00))
					throw new RuntimeException("Bad response on select identity file");
				ct.transmit(apduReadBinary);
				answer = ct.receive();
				LOG.debug(String.format("SELECT Read binary sent. Answer: %s", bytesToString(answer)));
				if (answer[answer.length - 2] == 0x6C) {//
					LOG.debug(String.format("SELECT Read binary: wrong expected length"));
				}
				apduReadBinary[4] = answer[answer.length -1];
			} while(answer[answer.length - 2] == 0x6C);
			ct.close();
		}
	}
	private String bytesToString(byte[] data) {
		String dataString = "";
		for (int j=0; j < data.length;j++)
			dataString += String.format("%2x ", data[j]);
		return dataString;
	}
	//@Test
	//public void waitForCardInsertion throws Exception {
	//	ArrayList<CCIDTerminal> ccidTerminals = listCCIDTerminals();
	//}
	
}
