jCryption.NET
=========

jCryption.NET is a server side implementation for ASP.NET and jQuery client side form data encryption library **jCryption**.

jCryption was originally created by Daniel Griesser http://www.jcryption.org/

jCryption provides an easy way to encrypt form data posted to an unsecure server through HTTP.

With 'typical' websites that have no HTTPS(SSL) method, you may sometimes want to hide some of form data content from public transport like public WiFi. jCryption is the solution that provides encryption of form data between client and server without expensive SSL/HTTPS server certificate.

What's notable of this ASP.NET server side library:
====

  - Respecting original jCryption protocol (OpenSSL PEM style format and negotiation)
  - OpenSSL independent ( using .NET native RSA/AES crypto library )
  - RSA keys are automatically generated
  - Integration with ASPX and CSHTML (WebPages) Request.Form is automatically replaced with decrypted content.
  - Silently deactivates under HTTPS secure connection ( with cshtml helper methods )
  - load initial form data through encryption ( with CSHTML helper )
   
  
Version
----
####1.1
 - jCryption version 3.1.0
 - secure form data loading ( on CSHTML )

####1.0.1
 - now works with jquery.validate

####1.0

Dependency
---
 - jQuery ( on which jCryption depends ) http://jquery.com/
 - jCryption 3.0.1 or later http://www.jcryption.org/
 - ASP.NET 4.0 or later
 - ( ASP.NET WebPages 2.0 or later )

Installation
---

 - App_Code/jCryption.cs
 - Scripts/jquery.jcryption.3.1.0.js
 

Integration Examples
---


###ASPX
Make ASPX page inherit jCryption.SecurePage. SecurePage handles the negotiations with jCryption client javascript library. Javascript initialization should be placed so that 'getKeysURL' and 'handshakeURL' can access the Page.

```aspx
<%@  Language="C#" Inherits="jCryption.SecurePage" %>
<html>
    <head>
        <script type="text/javascript" src="//ajax.googleapis.com/ajax/libs/jquery/2.0.3/jquery.min.js"></script>
		<script type="text/javascript" src="Scripts/jquery.jcryption.3.1.0.js"></script>
		<script type="text/javascript">
		    $(function () {
		        $("#normal").jCryption({
		            getKeysURL: "<%= Request.Path %>?getPublicKey=true",
		            handshakeURL: "<%= Request.Path %>?handshake=true"
		        });
		    });
		</script>
	</head>
......

```

###CSHTML
 1. declare namespace access to 'jCryption' on the top of page.```@using jCryption```
 2. call ```jCryption.HandleRequest(Request)``` on the top of page to handle all background negotiations.
 3. include all depending scripts ( jQuery )
 3. call ```@jCryption.RenderScriptFor("jQuery selector for form", "path to jcryption.js *optional*")``` in the page ( typically in head ). ( in the case with jquery validate, code should be placed after jquery.validate include. )

 


```cs
@using jCryption
@{
    jCryption.HandleRequest(Request);
}
<!doctype html>
<html>
<head>
    <script type="text/javascript" src="//ajax.googleapis.com/ajax/libs/jquery/2.0.3/jquery.min.js"></script>
    @jCryption.RenderScriptFor("#normal", "Scripts/jquery.jcryption.3.1.0.js")
</head>
......
<form id="normal">
.....
</form>
......

```

###CSHTML page with secure initial form data loading
jCryption provides a way to encrypt client to server data transfer but it does not protect form values that are initially rendered by server in a HTML form like ```<input name='Name' value='Smith' />```

This library provides some more methods to protect server to client transfered form data. 

####@jCryption.SecureNameValue( String name, String value )

is used to decorate name and value attributes in ```<input>```.

```<input type='text' @jCryption.SecureNameValue("Name", "Smith") />```

####@jCryption.SecureNameValueCheck( String name, String value, bool check )
is used for checkbox and radio type input element.

```
    <input type='checkbox' @jCryption.SecureNameValueCheck("Animal", "Dog", true ) />
    <input type='checkbox' @jCryption.SecureNameValueCheck("Animal", "Cat", false ) />
```

####@jCryption.RenderLoadFormData()
must be placed after all SecureNameValue* funtion calls.
This renders a javascript block with encrypted form values, which are to be decrypted through server-client negotiation. Form elements are filled in javascript calls.

License
----

MIT

[Jake Y.Yoshimura]: http://www.yo-ki.com/
