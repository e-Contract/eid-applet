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

package be.fedict.eid.applet.beta;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.net.URL;

import javax.ejb.EJB;
import javax.ejb.Remove;
import javax.ejb.Stateful;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;

import org.apache.commons.io.IOUtils;
import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Destroy;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Out;
import org.jboss.seam.log.Log;

import be.fedict.eid.applet.service.signer.ooxml.OOXMLSignatureVerifier;

@Stateful
@Name("ooxmlUploader")
@LocalBinding(jndiBinding = "fedict/eid/applet/beta/OOXMLUploaderBean")
public class OOXMLUploaderBean implements OOXMLUploader {

	@Logger
	private Log log;

	private String fileName;

	private InputStream uploadedFile;

	@EJB
	private TempFileManager tempFileManager;

	@SuppressWarnings("unused")
	@Out(scope = ScopeType.SESSION, required = false)
	private String ooxmlFileName;

	@In
	private FacesContext facesContext;

	@Remove
	@Destroy
	public void destroy() {
		this.log.debug("destroy");
	}

	public String getFileName() {
		return this.fileName;
	}

	public InputStream getUploadedFile() {
		return this.uploadedFile;
	}

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

	public void setUploadedFile(InputStream uploadedFile) {
		this.uploadedFile = uploadedFile;
	}

	public String upload() {
		this.log.debug("upload: " + this.fileName);
		this.ooxmlFileName = this.fileName;
		try {
			URL tmpFileUrl = this.tempFileManager
					.createTempFile(OOXML_URL_SESSION_ATTRIBUTE);
			File tmpFile = new File(tmpFileUrl.toURI());
			OutputStream outputStream = new FileOutputStream(tmpFile);
			IOUtils.copy(this.uploadedFile, outputStream);
			if (false == OOXMLSignatureVerifier.isOOXML(tmpFileUrl)) {
				this.facesContext.addMessage(null, new FacesMessage(
						"not an OOXML document"));
				return null;
			}
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage(), e);
		} catch (URISyntaxException e) {
			throw new RuntimeException("URI error: " + e.getMessage(), e);
		}
		return "success";
	}
}
