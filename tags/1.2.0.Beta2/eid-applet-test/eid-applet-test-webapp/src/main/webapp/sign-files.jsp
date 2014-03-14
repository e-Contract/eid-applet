<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<html>
<head>
<title>eID Applet File Signature Test</title>
</head>
<body>
<h1>eID Applet File Signature Test</h1>
<form method="post" action="sign-files-applet.jsp">
<p>Signature Algorithm: <select name="signDigestAlgo">
	<option value="SHA-1" selected="selected">SHA-1 with RSA</option>
	<option value="SHA-224">SHA-224 with RSA</option>
	<option value="SHA-256">SHA-256 with RSA</option>
	<option value="SHA-384">SHA-384 with RSA</option>
	<option value="SHA-512">SHA-512 with RSA</option>
	<option value="RIPEMD128">RIPEMD128 with RSA</option>
	<option value="RIPEMD160">RIPEMD160 with RSA</option>
	<option value="RIPEMD256">RIPEMD256 with RSA</option>
</select></p>
<p>Digest Algorithm for the files: <select name="filesDigestAlgo">
	<option value="SHA-1" selected="selected">SHA-1</option>
	<option value="SHA-256">SHA-256</option>
	<option value="SHA-384">SHA-384</option>
	<option value="SHA-512">SHA-512</option>
</select></p>
<p><input type="submit" value="Continue" /></p>
</form>
</body>
</html>