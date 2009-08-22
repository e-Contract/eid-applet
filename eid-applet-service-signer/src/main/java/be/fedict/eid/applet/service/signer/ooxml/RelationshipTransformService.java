/*
 * eID Applet Project.
 * Copyright (C) 2009 FedICT.
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

package be.fedict.eid.applet.service.signer.ooxml;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.LinkedList;
import java.util.List;

import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Constants;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class RelationshipTransformService extends TransformService {

	public static final String TRANSFORM_URI = "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";

	private final List<String> sourceIds;

	private static final Log LOG = LogFactory
			.getLog(RelationshipTransformService.class);

	public RelationshipTransformService() {
		super();
		LOG.debug("constructor");
		this.sourceIds = new LinkedList<String>();
	}

	@Override
	public void init(TransformParameterSpec params)
			throws InvalidAlgorithmParameterException {
		LOG.debug("init(params)");
	}

	@Override
	public void init(XMLStructure parent, XMLCryptoContext context)
			throws InvalidAlgorithmParameterException {
		LOG.debug("init(parent,context)");
		LOG.debug("parent java type: " + parent.getClass().getName());
		DOMStructure domParent = (DOMStructure) parent;
		Node parentNode = domParent.getNode();
		try {
			LOG.debug("parent: " + toString(parentNode));
		} catch (TransformerException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		Element nsElement = parentNode.getOwnerDocument().createElement("ns");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:ds",
				Constants.SignatureSpecNS);
		nsElement
				.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:mdssi",
						"http://schemas.openxmlformats.org/package/2006/digital-signature");
		NodeList nodeList;
		try {
			nodeList = XPathAPI.selectNodeList(parentNode,
					"mdssi:RelationshipReference/@SourceId", nsElement);
		} catch (TransformerException e) {
			LOG.error("transformer exception: " + e.getMessage(), e);
			throw new InvalidAlgorithmParameterException();
		}
		for (int nodeIdx = 0; nodeIdx < nodeList.getLength(); nodeIdx++) {
			Node node = nodeList.item(nodeIdx);
			String sourceId = node.getTextContent();
			LOG.debug("sourceId: " + sourceId);
			this.sourceIds.add(sourceId);
		}
	}

	static String toString(Node dom) throws TransformerException {
		Source source = new DOMSource(dom);
		StringWriter stringWriter = new StringWriter();
		Result result = new StreamResult(stringWriter);
		TransformerFactory transformerFactory = TransformerFactory
				.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		/*
		 * We have to omit the ?xml declaration if we want to embed the
		 * document.
		 */
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		transformer.transform(source, result);
		return stringWriter.getBuffer().toString();
	}

	@Override
	public void marshalParams(XMLStructure parent, XMLCryptoContext context)
			throws MarshalException {
		LOG.debug("marshallParams");
	}

	public AlgorithmParameterSpec getParameterSpec() {
		LOG.debug("getParameterSpec");
		return null;
	}

	public Data transform(Data data, XMLCryptoContext context)
			throws TransformException {
		LOG.debug("transform(data,context)");
		LOG.debug("data java type: " + data.getClass().getName());
		OctetStreamData octetStreamData = (OctetStreamData) data;
		LOG.debug("URI: " + octetStreamData.getURI());
		InputStream octetStream = octetStreamData.getOctetStream();
		Document relationshipsDocument;
		try {
			relationshipsDocument = loadDocument(octetStream);
		} catch (Exception e) {
			throw new TransformException(e.getMessage(), e);
		}
		try {
			LOG.debug("relationships document: "
					+ toString(relationshipsDocument));
		} catch (TransformerException e) {
			throw new TransformException(e.getMessage(), e);
		}
		Element nsElement = relationshipsDocument.createElement("ns");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:tns",
				"http://schemas.openxmlformats.org/package/2006/relationships");
		URIDereferencer uriDereferencer = context.getURIDereferencer();
		for (String sourceId : this.sourceIds) {
			LOG.debug("source Id: " + sourceId);
			Node targetNode;
			try {
				targetNode = XPathAPI.selectSingleNode(relationshipsDocument,
						"tns:Relationships/tns:Relationship[@Id='" + sourceId
								+ "']/@Target", nsElement);
			} catch (TransformerException e) {
				LOG.error(e.getMessage(), e);
				throw new TransformException(e.getMessage(), e);
			}
			String target = targetNode.getTextContent();
			LOG.debug("target: " + target);
			Data referedData;
			try {
				referedData = uriDereferencer.dereference(
						new SimpleURIReference(target), context);
			} catch (URIReferenceException e) {
				throw new TransformException(e.getMessage(), e);
			}
			LOG.debug("data java type: " + referedData.getClass().getName());
			OctetStreamData referedOctetStreamData = (OctetStreamData) referedData;
			InputStream referedInputStream = referedOctetStreamData
					.getOctetStream();
			// TODO: concat different sources
			return new OctetStreamData(referedInputStream);
		}
		return null;
	}

	private static class SimpleURIReference implements URIReference {

		private final String uri;

		public SimpleURIReference(String uri) {
			this.uri = uri;
		}

		public String getType() {
			return null;
		}

		public String getURI() {
			return this.uri;
		}
	}

	private Document loadDocument(InputStream documentInputStream)
			throws ParserConfigurationException, SAXException, IOException {
		InputSource inputSource = new InputSource(documentInputStream);
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder.parse(inputSource);
		return document;
	}

	public Data transform(Data data, XMLCryptoContext context, OutputStream os)
			throws TransformException {
		LOG.debug("transform(data,context,os)");
		return null;
	}

	public boolean isFeatureSupported(String feature) {
		LOG.debug("isFeatureSupported(feature)");
		return false;
	}
}
