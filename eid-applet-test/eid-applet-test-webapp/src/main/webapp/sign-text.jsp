<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<html>
<head>
<title>eID Applet Signature Demo</title>
</head>
<body>
<h1>eID Applet Signature Demo</h1>
<form method="post" action="sign.jsp">
<p>Text message to be signed:</p>
<textarea rows="10" cols="60" name="toBeSigned"></textarea>
<p>Signature Algorithm: <select name="digestAlgo">
	<option value="SHA-1" selected="selected">SHA-1 with RSA</option>
	<option value="SHA-224">SHA-224 with RSA</option>
	<option value="SHA-256">SHA-256 with RSA</option>
	<option value="SHA-384">SHA-384 with RSA</option>
	<option value="SHA-512">SHA-512 with RSA</option>
	<option value="RIPEMD128">RIPEMD128 with RSA</option>
	<option value="RIPEMD160">RIPEMD160 with RSA</option>
	<option value="RIPEMD256">RIPEMD256 with RSA</option>
	<option value="SHA-1-PSS">SHA-1 with RSA/PSS</option>
	<option value="SHA-256-PSS">SHA-256 with RSA/PSS</option>
</select></p>
<p><input type="submit" value="Sign" /></p>
</form>
</body>
</html>