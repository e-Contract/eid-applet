<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Identity Result Page</title>
<script type="text/javascript" language="javascript">
var xmlHttpRequest = false;

function makeRequest(url) {
   xmlHttpRequest = false;
   if (window.XMLHttpRequest) {
	   xmlHttpRequest = new XMLHttpRequest();
      if (xmlHttpRequest.overrideMimeType) {
    	  //xmlHttpRequest.overrideMimeType('text/xml');
      }
   } else if (window.ActiveXObject) {
      try {
    	  xmlHttpRequest = new ActiveXObject("Msxml2.XMLHTTP");
      } catch (e) {
         try {
        	 xmlHttpRequest = new ActiveXObject("Microsoft.XMLHTTP");
         } catch (e) {}
      }
   }
   if (!xmlHttpRequest) {
      alert('Cannot create XMLHttpRequest instance');
      return false;
   }
   xmlHttpRequest.onreadystatechange = stateChanged;
   xmlHttpRequest.open('GET', url, true);
   xmlHttpRequest.send(null);
}


function stateChanged() {
	if (4 == xmlHttpRequest.readyState) {
	  	if (200 == xmlHttpRequest.status) {
	  		var response = eval("(" + xmlHttpRequest.responseText + ")");
	  		
	  		var nameDiv = document.getElementById("name");
	  		nameDiv.innerHTML = "Name: " + response.identity.name;

	  		var firstNameDiv = document.getElementById("firstName");
	  		firstNameDiv.innerHTML = "First name: " + response.identity.firstName;

	  		var dateOfBirthDiv = document.getElementById("dateOfBirth");
	  		dateOfBirthDiv.innerHTML = "Date Of Birth: " + response.identity.dateOfBirth;

	  		var genderDiv = document.getElementById("gender");
	  		genderDiv.innerHTML = "Gender: " + response.identity.gender;

	  		var streetAndNumberDiv = document.getElementById("streetAndNumber");
	  		streetAndNumberDiv.innerHTML = "Street And Number: " + response.address.streetAndNumber;

	  		var municipalityDiv = document.getElementById("municipality");
	  		municipalityDiv.innerHTML = "Municipality: " + response.address.municipality;

	  		var zipDiv = document.getElementById("zip");
	  		zipDiv.innerHTML = "ZIP: " + response.address.zip;
	  	} else {
	    	alert("Problem retrieving XML data: " + xmlHttpRequest.status + ": " + xmlHttpRequest.statusText);
		}
	}
}

function getResults() {
	makeRequest("identity.js");
}
</script>
</head>
<body>
<h1>Identity Result Page</h1>
<p>The page will demo the eID identification results via AJAX/JSON.</p>
<div id="name"></div>
<div id="firstName"></div>
<div id="dateOfBirth"></div>
<div id="gender"></div>
<div id="streetAndNumber"></div>
<div id="municipality"></div>
<div id="zip"></div>

<form><input type="button" value="Get Results"
	onclick="javascript:getResults();" /></form>
<p><a href="identify-json.jsp">Again</a> | <a href=".">Main Page</a>
</p>
</body>
</html>