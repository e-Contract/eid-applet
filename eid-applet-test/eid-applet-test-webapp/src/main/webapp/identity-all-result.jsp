<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@page import="be.fedict.eid.applet.service.Identity"%>
<%@page import="be.fedict.eid.applet.service.Address"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Identity Result Page</title>
</head>
<body>
<h1>Identity Result Page</h1>
<h2>Identity Information</h2>
<img src="photo" />
<table>
	<tr>
		<th>Attribute</th>
		<th>Value</th>
	</tr>
	<tr>
		<td>Name</td>
		<td><%=((Identity) session.getAttribute("eid.identity")).name%></td>
	</tr>
	<tr>
		<td>First name</td>
		<td><%=((Identity) session.getAttribute("eid.identity")).firstName%></td>
	</tr>
	<tr>
		<td>Middle name</td>
		<td><%=((Identity) session.getAttribute("eid.identity")).middleName%></td>
	</tr>
	<tr>
		<td>Card Number</td>
		<td><%=((Identity) session.getAttribute("eid.identity")).cardNumber%></td>
	</tr>
	<tr>
		<td>Chip Number</td>
		<td><%=((Identity) session.getAttribute("eid.identity")).chipNumber%></td>
	</tr>
	<tr>
		<td>Card Validity Date Begin</td>
		<td><%=((Identity) session.getAttribute("eid.identity")).cardValidityDateBegin
									.getTime()%></td>
	</tr>
	<tr>
		<td>Card Validity Date End</td>
		<td><%=((Identity) session.getAttribute("eid.identity")).cardValidityDateEnd
									.getTime()%></td>
	</tr>
	<tr>
		<td>Card Delivery Municipality</td>
		<td><%=((Identity) session.getAttribute("eid.identity")).cardDeliveryMunicipality%></td>
	</tr>
	<tr>
		<td>National Number</td>
		<td><%=((Identity) session.getAttribute("eid.identity")).nationalNumber%></td>
	</tr>
	<tr>
		<td>Nationality</td>
		<td><%=((Identity) session.getAttribute("eid.identity")).nationality%></td>
	</tr>
	<tr>
		<td>Place Of Birth</td>
		<td><%=((Identity) session.getAttribute("eid.identity")).placeOfBirth%></td>
	</tr>
	<tr>
		<td>Date Of Birth</td>
		<td><%=((Identity) session.getAttribute("eid.identity")).dateOfBirth
									.getTime()%></td>
	</tr>
	<tr>
		<td>Gender</td>
		<td><%=((Identity) session.getAttribute("eid.identity")).gender%></td>
	</tr>
	<tr>
		<td>Document Type</td>
		<td><%=((Identity) session.getAttribute("eid.identity")).documentType%></td>
	</tr>
	<tr>
		<td>Special Status</td>
		<td><%=((Identity) session.getAttribute("eid.identity")).specialStatus%></td>
	</tr>
	<tr>
		<td>Noble Condition</td>
		<td><%=((Identity) session.getAttribute("eid.identity")).nobleCondition%></td>
	</tr>
	<tr>
		<td>Street and number</td>
		<td><%=((Address) session.getAttribute("eid.address")).streetAndNumber%></td>
	</tr>
	<tr>
		<td>ZIP</td>
		<td><%=((Address) session.getAttribute("eid.address")).zip%></td>
	</tr>
	<tr>
		<td>Municipality</td>
		<td><%=((Address) session.getAttribute("eid.address")).municipality%></td>
	</tr>
</table>
<h2>Secure Client Environment Information</h2>
<table>
	<tr>
		<th>Attribute</th>
		<th>Value</th>
	</tr>
	<tr>
		<td>Client Java Version</td>
		<td><%=session.getAttribute("ClientJavaVersion")%></td>
	</tr>
	<tr>
		<td>Client Java Vendor</td>
		<td><%=session.getAttribute("ClientJavaVendor")%></td>
	</tr>
	<tr>
		<td>Client OS Name</td>
		<td><%=session.getAttribute("ClientOSName")%></td>
	</tr>
	<tr>
		<td>Client OS Architecture</td>
		<td><%=session.getAttribute("ClientOSArch")%></td>
	</tr>
	<tr>
		<td>Client OS Version</td>
		<td><%=session.getAttribute("ClientOSVersion")%></td>
	</tr>
	<tr>
		<td>Client Readers</td>
		<td><%=session.getAttribute("ClientReaders")%></td>
	</tr>
	<tr>
		<td>Client User Agent</td>
		<td><%=session.getAttribute("ClientUserAgent")%></td>
	</tr>
	<tr>
		<td>Client Navigator User Agent</td>
		<td><%=session.getAttribute("ClientNavigatorUserAgent")%></td>
	</tr>
	<tr>
		<td>Client Navigator App Name</td>
		<td><%=session.getAttribute("ClientNavigatorAppName")%></td>
	</tr>
	<tr>
		<td>Client Navigator App Version</td>
		<td><%=session.getAttribute("ClientNavigatorAppVersion")%></td>
	</tr>
	<tr>
		<td>Client SSL Cipher Suite</td>
		<td><%=session.getAttribute("ClientSslCipherSuite")%></td>
	</tr>
	<tr>
		<td>Client SSL Key Size</td>
		<td><%=session.getAttribute("ClientSslKeySize")%></td>
	</tr>
	<tr>
		<td>Client Remote Address</td>
		<td><%=session.getAttribute("ClientRemoteAddress")%></td>
	</tr>
</table>

<h2>Identity Integrity</h2>
National Registry Certificate:
<pre>
<%=session.getAttribute("NationalRegistryCertificate")%>
</pre>

<h2>Certificates</h2>
Authentication Certificate:
<pre>
<%=session.getAttribute("eid.certs.authn")%>
</pre>
Signature Certificate:
<pre>
<%=session.getAttribute("eid.certs.sign")%>
</pre>
Citizen CA Certificate:
<pre>
<%=session.getAttribute("eid.certs.ca")%>
</pre>
Root CA Certificate:
<pre>
<%=session.getAttribute("eid.certs.root")%>
</pre>

<p><a href="identity.pdf">Identity in PDF</a></p>
<a href="identify-all.jsp">Again</a>
|
<a href=".">Main Page</a>
</body>
</html>