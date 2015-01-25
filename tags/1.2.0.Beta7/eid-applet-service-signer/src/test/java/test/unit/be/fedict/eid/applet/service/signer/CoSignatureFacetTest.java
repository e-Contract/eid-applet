/*
 * eID Applet Project.
 * Copyright (C) 2010 FedICT.
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

package test.unit.be.fedict.eid.applet.service.signer;

import be.fedict.eid.applet.service.signer.DigestAlgo;
import be.fedict.eid.applet.service.signer.facets.CoSignatureFacet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.xml.security.utils.Constants;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.security.KeyPair;
import java.util.LinkedList;
import java.util.List;

import static org.junit.Assert.*;

public class CoSignatureFacetTest {

	private static final Log LOG = LogFactory
			.getLog(CoSignatureFacetTest.class);

	@Test
	public void testCoSignature() throws Exception {
		// setup
		Document document = PkiTestUtils
				.loadDocument(CoSignatureFacetTest.class
						.getResourceAsStream("/helloworld.xml"));
		KeyPair keyPair = PkiTestUtils.generateKeyPair();

		XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance(
				"DOM", new XMLDSigRI());

		XMLSignContext signContext = new DOMSignContext(keyPair.getPrivate(),
				document.getDocumentElement());
		signContext.putNamespacePrefix(
				javax.xml.crypto.dsig.XMLSignature.XMLNS, "ds");

		CoSignatureFacet testedInstance = new CoSignatureFacet();
		List<Reference> references = new LinkedList<Reference>();
		testedInstance.preSign(signatureFactory, document, "foo-bar", null,
				references, null);

		SignatureMethod signatureMethod = signatureFactory.newSignatureMethod(
				SignatureMethod.RSA_SHA1, null);
		CanonicalizationMethod canonicalizationMethod = signatureFactory
				.newCanonicalizationMethod(
						CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS,
						(C14NMethodParameterSpec) null);
		SignedInfo signedInfo = signatureFactory.newSignedInfo(
				canonicalizationMethod, signatureMethod, references);

		XMLSignature xmlSignature = signatureFactory.newXMLSignature(
				signedInfo, null);

		// operate
		xmlSignature.sign(signContext);

		// verify
		LOG.debug("signed document: " + PkiTestUtils.toString(document));
		NodeList signatureNodeList = document.getElementsByTagNameNS(
				XMLSignature.XMLNS, "Signature");
		assertEquals(1, signatureNodeList.getLength());
		Node signatureNode = signatureNodeList.item(0);
		DOMValidateContext domValidateContext = new DOMValidateContext(
				keyPair.getPublic(), signatureNode);
		XMLSignature validationXmlSignature = signatureFactory
				.unmarshalXMLSignature(domValidateContext);
		boolean validity = validationXmlSignature.validate(domValidateContext);
		assertTrue(validity);

		document.getDocumentElement().getFirstChild().setNodeValue("test");
		LOG.debug("signed document: " + PkiTestUtils.toString(document));
		assertTrue(validationXmlSignature.validate(domValidateContext));
		// really have to re-load the XML signature object.
		validationXmlSignature = signatureFactory
				.unmarshalXMLSignature(domValidateContext);
		assertFalse(validationXmlSignature.validate(domValidateContext));
	}

	@Test
	public void testCoSignatureUri() throws Exception {
		// setup
		Document document = PkiTestUtils
				.loadDocument(CoSignatureFacetTest.class
						.getResourceAsStream("/helloworld.xml"));
		KeyPair keyPair = PkiTestUtils.generateKeyPair();

		XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance(
				"DOM", new XMLDSigRI());

		XMLSignContext signContext = new DOMSignContext(keyPair.getPrivate(),
				document.getDocumentElement());
		signContext.putNamespacePrefix(
				javax.xml.crypto.dsig.XMLSignature.XMLNS, "ds");

		CoSignatureFacet testedInstance = new CoSignatureFacet(DigestAlgo.SHA1,
				"ref-1234");
		List<Reference> references = new LinkedList<Reference>();
		testedInstance.preSign(signatureFactory, document, "foo-bar", null,
				references, null);

		SignatureMethod signatureMethod = signatureFactory.newSignatureMethod(
				SignatureMethod.RSA_SHA1, null);
		CanonicalizationMethod canonicalizationMethod = signatureFactory
				.newCanonicalizationMethod(
						CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS,
						(C14NMethodParameterSpec) null);
		SignedInfo signedInfo = signatureFactory.newSignedInfo(
				canonicalizationMethod, signatureMethod, references);

		XMLSignature xmlSignature = signatureFactory.newXMLSignature(
				signedInfo, null);

		// operate
		xmlSignature.sign(signContext);

		// verify
		LOG.debug("signed document: " + PkiTestUtils.toString(document));
		NodeList signatureNodeList = document.getElementsByTagNameNS(
				XMLSignature.XMLNS, "Signature");
		assertEquals(1, signatureNodeList.getLength());
		Node signatureNode = signatureNodeList.item(0);
		DOMValidateContext domValidateContext = new DOMValidateContext(
				keyPair.getPublic(), signatureNode);
		XMLSignature validationXmlSignature = signatureFactory
				.unmarshalXMLSignature(domValidateContext);
		boolean validity = validationXmlSignature.validate(domValidateContext);
		assertTrue(validity);

		document.getDocumentElement().getFirstChild().setNodeValue("test");
		LOG.debug("signed document: " + PkiTestUtils.toString(document));
		assertTrue(validationXmlSignature.validate(domValidateContext));
		// really have to re-load the XML signature object.
		validationXmlSignature = signatureFactory
				.unmarshalXMLSignature(domValidateContext);
		assertFalse(validationXmlSignature.validate(domValidateContext));
	}

	@Test
	public void testMultipleCoSignatures() throws Exception {

		// setup
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
                .newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory
                .newDocumentBuilder();
        Document document = documentBuilder.newDocument();
        Element rootElement = document.createElementNS("urn:test", "tns:root");
        rootElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:tns",
                "urn:test");
        document.appendChild(rootElement);
        Element dataElement = document.createElementNS("urn:test", "tns:data");
        rootElement.appendChild(dataElement);

        // add alot of nodes to test performance
        // when using xpath v1 in the co signature facet the c14n became really slow
        for (int i = 0; i < 80000; i++) {
            Element fooElement = document.createElementNS("urn:test", "tns:foo");
            fooElement.setTextContent("bar");
            dataElement.appendChild(fooElement);
        }

		KeyPair keyPair1 = PkiTestUtils.generateKeyPair();
		KeyPair keyPair2 = PkiTestUtils.generateKeyPair();

		XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance(
				"DOM", new XMLDSigRI());
		List<Reference> references = new LinkedList<Reference>();

		CoSignatureFacet testedInstance = new CoSignatureFacet();
		testedInstance.preSign(signatureFactory, document, "foo-bar", null,
				references, null);

		// ds:SignedInfo
		SignatureMethod signatureMethod = signatureFactory.newSignatureMethod(
				SignatureMethod.RSA_SHA1, null);
		CanonicalizationMethod canonicalizationMethod = signatureFactory
				.newCanonicalizationMethod(
						CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS,
						(C14NMethodParameterSpec) null);
		SignedInfo signedInfo = signatureFactory.newSignedInfo(
				canonicalizationMethod, signatureMethod, references);

		XMLSignature xmlSignature = signatureFactory.newXMLSignature(
				signedInfo, null);
		XMLSignature xmlSignature2 = signatureFactory.newXMLSignature(
				signedInfo, null);

		// sign context
		XMLSignContext signContext1 = new DOMSignContext(keyPair1.getPrivate(),
				document.getDocumentElement());
		signContext1.putNamespacePrefix(
				javax.xml.crypto.dsig.XMLSignature.XMLNS, "ds");

		XMLSignContext signContext2 = new DOMSignContext(keyPair2.getPrivate(),
				document.getDocumentElement());
		signContext2.putNamespacePrefix(
				javax.xml.crypto.dsig.XMLSignature.XMLNS, "ds");

		// operate
		xmlSignature.sign(signContext1);
		xmlSignature2.sign(signContext2);

		// verify
		LOG.debug("signed document: " + PkiTestUtils.toString(document));
		NodeList signatureNodeList = document.getElementsByTagNameNS(
				XMLSignature.XMLNS, "Signature");
		assertEquals(2, signatureNodeList.getLength());
		Node signature1Node = signatureNodeList.item(0);
		DOMValidateContext domValidateContext1 = new DOMValidateContext(
				keyPair1.getPublic(), signature1Node);
		XMLSignature validationXmlSignature1 = signatureFactory
				.unmarshalXMLSignature(domValidateContext1);
		boolean validity1 = validationXmlSignature1
				.validate(domValidateContext1);
		assertTrue(validity1);

		Node signature2Node = signatureNodeList.item(1);
		DOMValidateContext domValidateContext2 = new DOMValidateContext(
				keyPair2.getPublic(), signature2Node);
		XMLSignature validationXmlSignature2 = signatureFactory
				.unmarshalXMLSignature(domValidateContext2);
		boolean validity2 = validationXmlSignature2
				.validate(domValidateContext2);
		assertTrue(validity2);

		// cut out first signature should not break second one
		document.getDocumentElement().removeChild(signature1Node);
		LOG.debug("signed document: " + PkiTestUtils.toString(document));
		NodeList signatureNodeList2 = document.getElementsByTagNameNS(
				XMLSignature.XMLNS, "Signature");
		assertEquals(1, signatureNodeList2.getLength());

		Node signature3Node = signatureNodeList2.item(0);
		DOMValidateContext domValidateContext3 = new DOMValidateContext(
				keyPair2.getPublic(), signature3Node);
		XMLSignature validationXmlSignature3 = signatureFactory
				.unmarshalXMLSignature(domValidateContext3);
		boolean validity3 = validationXmlSignature3
				.validate(domValidateContext3);
		assertTrue(validity3);
	}
}
