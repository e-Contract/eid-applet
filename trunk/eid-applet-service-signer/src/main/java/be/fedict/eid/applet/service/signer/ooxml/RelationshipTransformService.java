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

import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class RelationshipTransformService extends TransformService {

	public static final String TRANSFORM_URI = "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";

	private static final Log LOG = LogFactory
			.getLog(RelationshipTransformService.class);

	@Override
	public void init(TransformParameterSpec params)
			throws InvalidAlgorithmParameterException {
		LOG.debug("init(params)");
	}

	@Override
	public void init(XMLStructure parent, XMLCryptoContext context)
			throws InvalidAlgorithmParameterException {
		LOG.debug("init(parent,context)");
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
		return null;
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
