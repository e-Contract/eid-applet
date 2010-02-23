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

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.EIdData;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.PdfServlet;

import com.lowagie.text.BadElementException;
import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.Image;
import com.lowagie.text.Paragraph;

import com.lowagie.text.pdf.Barcode128;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;

/**
 * PDF generator for eID identity data. The implementation is using iText.
 * 
 * @author Frank Cornelis
 * @author Bart Hanssens
 * @see PdfServlet
 */
public class PdfGenerator {

	private static final Log LOG = LogFactory.getLog(PdfGenerator.class);

        /**
         * Generate a Code128C barcode
         *
         * @param rrn unique Rijksregister number
         * @param cardNumber number of the card
         * @return Image containing barcode
         * @throws IOException
         * @throws BadElementException
         */
        private Image createBarcodeImage(String rrn, String cardNumber) throws IOException, BadElementException {
            if (null == rrn || rrn.length() != 11  ||
                    null == cardNumber || cardNumber.length() < 9) {
                throw new IllegalArgumentException("Missing or invalid length for RRN or Card Number");
            }

            String lastDigits = cardNumber.substring(cardNumber.length() - 9);
            String code = rrn + lastDigits;

            Barcode128 barcode = new Barcode128();
            barcode.setCodeType(Barcode128.CODE_C);
            barcode.setCode(code);
            barcode.setFont(null);

            return Image.getInstance(barcode.createAwtImage(Color.BLACK, Color.WHITE), null, true);
        }


        /**
         * Create a PDF image from eID photo
         *
         * @param photoData raw bytes
         * @return PDF image
         * @throws IOException
         * @throws BadElementException
         */
        private Image createImageFromPhoto(byte[] photoData) throws IOException, BadElementException {
            Image image = Image.getInstance(photoData);
            image.setAlt("Photo");
            image.setAlignment(Element.ALIGN_CENTER);
            image.setSpacingAfter(20);

            return image;
        }


        /**
         * Set the metadata on the PDF document
         * 
         * @param doc PDF document
         * @param firstName first name of the person
         * @param lastName last name of the person
         */
        private void setDocumentMetadata(Document doc, String firstName, String lastName) {
            doc.addTitle(firstName + " " + lastName);
            doc.addSubject("Data from the eID card");
            doc.addCreator("Belgian eID applet");
            doc.addProducer();
            doc.addCreationDate();
        }


	public byte[] generatePdf(EIdData eIdData) throws DocumentException {
            Document document = new Document();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PdfWriter writer = PdfWriter.getInstance(document, baos);

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
                    try {
                        Image image = createImageFromPhoto(eIdData.getPhoto());
                        document.add(image);
                    } catch (Exception e) {
                        LOG.error("Error getting photo: " + e.getMessage());
                    }

                    Identity identity = eIdData.getIdentity();

                    // metadata
                    setDocumentMetadata(document, identity.firstName, identity.name);
                    writer.createXmpMetadata();

                    // create a table with the data of the eID card
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

                    // TODO: to be tested
                    /*
                    try {
                        Image barcodeImage =
                            createBarcodeImage(identity.nationalNumber, identity.cardNumber);

                        barcodeImage.setAlignment(Element.ALIGN_CENTER);
                        Paragraph barcodePara = new Paragraph();
                        barcodePara.add(barcodeImage);

                        document.add(barcodeImage);
                    } catch (Exception e) {
                        LOG.error("Error adding barcode: " + e.getMessage());
                    }
                    */
		} else {
                    document.add(new Paragraph("No eID identity data available."));
		}
            }
            document.close();
            return baos.toByteArray();
	}
}
