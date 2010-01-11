/*
 * eID Digital Signature Service Project.
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

package be.fedict.eid.applet.service.signer.facets;

import javax.xml.crypto.dsig.XMLSignature;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sun.xml.bind.marshaller.NamespacePrefixMapper;

/**
 * JAXB RI namespace prefix mapper for XAdES.
 * 
 * @author fcorneli
 * 
 */
public class XAdESNamespacePrefixMapper extends NamespacePrefixMapper {

	private static final Log LOG = LogFactory
			.getLog(XAdESNamespacePrefixMapper.class);

	@Override
	public String getPreferredPrefix(String namespaceUri, String suggestion,
			boolean requirePrefix) {
		LOG.debug("namespace: " + namespaceUri);
		LOG.debug("suggestion: " + suggestion);
		LOG.debug("require prefix: " + requirePrefix);
		if (XMLSignature.XMLNS.equals(namespaceUri)) {
			return "ds";
		}
		return suggestion;
	}
}
