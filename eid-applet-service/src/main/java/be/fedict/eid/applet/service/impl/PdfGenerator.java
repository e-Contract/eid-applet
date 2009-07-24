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

package be.fedict.eid.applet.service.impl;

import java.io.ByteArrayOutputStream;
import java.text.SimpleDateFormat;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.EIdData;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.PdfServlet;

import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.Image;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;

/**
 * PDF generator for eID identity data. The implementation is using iText.
 * 
 * @author fcorneli
 * @see PdfServlet
 */
public class PdfGenerator {

	private static final Log LOG = LogFactory.getLog(PdfGenerator.class);

	public byte[] generatePdf(EIdData eIdData) throws DocumentException {
		Document document = new Document();
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		PdfWriter.getInstance(document, baos);
		document.open();

		Paragraph titleParagraph = new Paragraph("eID Identity Data");
		titleParagraph.setAlignment(Paragraph.ALIGN_CENTER);
		Font titleFont = titleParagraph.getFont();
		titleFont.setSize((float) 20.0);
		titleFont.setStyle(Font.BOLD);
		titleParagraph.setSpacingAfter(20);
		document.add(titleParagraph);

		if (null != eIdData && null != eIdData.getIdentity()) {
			if (null != eIdData.getPhoto()) {
				byte[] photoData = eIdData.getPhoto();
				try {
					Image image = Image.getInstance(photoData);
					image.setAlignment(Element.ALIGN_CENTER);
					image.setSpacingAfter(20);
					document.add(image);
				} catch (Exception e) {
					LOG.debug("photo error: " + e.getMessage(), e);
					document.add(new Paragraph("Photo contains some errors."));
				}
			}

			Identity identity = eIdData.getIdentity();
			PdfPTable table = new PdfPTable(2);
			table.getDefaultCell().setBorder(0);

			table.addCell("Name");
			table.addCell(identity.name);

			table.addCell("First name");
			String firstName = identity.firstName;
			if (null != identity.middleName) {
				firstName += " " + identity.middleName;
			}
			table.addCell(firstName);

			table.addCell("Nationality");
			table.addCell(identity.nationality);

			table.addCell("National Registration Number");
			table.addCell(identity.nationalNumber);

			table.addCell("Gender");
			table.addCell(identity.gender.toString());

			table.addCell("Date of birth");
			SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy");
			table.addCell(formatter.format(identity.dateOfBirth.getTime()));

			table.addCell("Place of birth");
			table.addCell(identity.placeOfBirth);

			if (null != eIdData.getAddress()) {
				Address address = eIdData.getAddress();
				table.addCell("Address");
				PdfPCell cell = new PdfPCell();
				cell.setBorder(0);
				cell.addElement(new Paragraph(address.streetAndNumber));
				cell.addElement(new Paragraph(address.zip + " "
						+ address.municipality));
				table.addCell(cell);
			}

			document.add(table);
		} else {
			document.add(new Paragraph("No eID identity data available."));
		}
		document.close();
		return baos.toByteArray();
	}
}
