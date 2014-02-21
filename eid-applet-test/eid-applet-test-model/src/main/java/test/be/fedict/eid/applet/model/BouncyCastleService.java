/*
 * eID Applet Project.
 * Copyright (C) 2014 e-Contract.be BVBA.
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

package test.be.fedict.eid.applet.model;

import java.security.Security;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.ejb.Singleton;
import javax.ejb.Startup;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

@Singleton
@Startup
public class BouncyCastleService {
	private BouncyCastleProvider provider;

	@PostConstruct
	public void init() {
		if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
			this.provider = new BouncyCastleProvider();
			Security.addProvider(this.provider);
		}
	}

	@PreDestroy
	public void stop() {
		if (null != this.provider) {
			Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
			this.provider = null;
		}
	}

}
