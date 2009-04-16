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

using System;

namespace Be.FedICT.EID.Applet.Service {
	
	public class Identity {
		
		private string name;
		
		private string firstName;
		
		public Identity() {
		}		
		
		[TlvField(7)]
		public string Name {
			get {
				return this.name;
			}
			
			set {
				this.name = value;
			}
		}
		
		[TlvField(8)]
		public string FirstName {
			get {
				return this.firstName;
			}
			
			set {
				this.firstName = value;
			}
		}
	}
}
