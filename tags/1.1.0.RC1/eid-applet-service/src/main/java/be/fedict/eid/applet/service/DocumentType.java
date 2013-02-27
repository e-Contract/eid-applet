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

package be.fedict.eid.applet.service;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * Enumeration for eID Document Type.
 * 
 * @author Frank Cornelis
 * 
 */
public enum DocumentType implements Serializable {

	BELGIAN_CITIZEN("1"), KIDS_CARD("6"), BOOTSTRAP_CARD("7"), HABILITATION_CARD(
			"8"),

	/**
	 * Bewijs van inschrijving in het vreemdelingenregister – Tijdelijk verblijf
	 */
	FOREIGNER_A("11"),

	/**
	 * Bewijs van inschrijving in het vreemdelingenregister
	 */
	FOREIGNER_B("12"),

	/**
	 * Identiteitskaart voor vreemdeling
	 */
	FOREIGNER_C("13"),

	/**
	 * EG-Langdurig ingezetene
	 */
	FOREIGNER_D("14"),

	/**
	 * (Verblijfs)kaart van een onderdaan van een lidstaat der EEG Verklaring
	 * van inschrijving
	 */
	FOREIGNER_E("15"),

	/**
	 * Document ter staving van duurzaam verblijf van een EU onderdaan
	 */
	FOREIGNER_E_PLUS("16"),

	/**
	 * Kaart voor niet-EU familieleden van een EU-onderdaan of van een Belg
	 * Verblijfskaart van een familielid van een burger van de Unie
	 */
	FOREIGNER_F("17"),

	/**
	 * Duurzame verblijfskaart van een familielid van een burger van de Unie
	 */
	FOREIGNER_F_PLUS("18"),

	/**
	 * H. Europese blauwe kaart. Toegang en verblijf voor onderdanen van derde
	 * landen.
	 */
	EUROPEAN_BLUE_CARD_H("19");

	private final int key;

	private DocumentType(String value) {
		this.key = toKey(value);
	}

	private int toKey(String value) {
		char c1 = value.charAt(0);
		int key = c1 - '0';
		if (2 == value.length()) {
			key *= 10;
			char c2 = value.charAt(1);
			key += c2 - '0';
		}
		return key;
	}

	private static int toKey(byte[] value) {
		int key = value[0] - '0';
		if (2 == value.length) {
			key *= 10;
			key += value[1] - '0';
		}
		return key;
	}

	private static Map<Integer, DocumentType> documentTypes;

	static {
		Map<Integer, DocumentType> documentTypes = new HashMap<Integer, DocumentType>();
		for (DocumentType documentType : DocumentType.values()) {
			int encodedValue = documentType.key;
			if (documentTypes.containsKey(encodedValue)) {
				throw new RuntimeException("duplicate document type enum: "
						+ encodedValue);
			}
			documentTypes.put(encodedValue, documentType);
		}
		DocumentType.documentTypes = documentTypes;
	}

	public int getKey() {
		return this.key;
	}

	public static DocumentType toDocumentType(byte[] value) {
		int key = toKey(value);
		DocumentType documentType = DocumentType.documentTypes.get(key);
		/*
		 * If the key is unknown, we simply return null.
		 */
		return documentType;
	}

	public static String toString(byte[] documentTypeValue) {
		String str = Integer.toString(toKey(documentTypeValue));
		return str;
	}
}
