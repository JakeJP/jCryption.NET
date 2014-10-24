jCryption.NET
=========

jCryption.NET is a server side implementation for ASP.NET and jQuery client side form data encryption library **jCryption**.

jCryption was originally created by http://www.jcryption.org/

jCryption provides an easy way to encrypt form data posted to an unsecure server through HTTP.

With 'typical' websites that have no HTTPS(SSL) method, you may sometimes want to hide some of form data content from public transport like public WiFi. jCryption is the solution that provides encryption of form data between client and server without expensive SSL/HTTPS server certificate.

What's notable of this ASP.NET server side library:
====

  - Respecting original jCryption protocol (OpenSSL PEM style format and negotiation)
  - OpenSSL independent ( using .NET native RSA/AES crypto library )
  - Integration with ASPX and CSHTML (WebPages) Request.Form is automatically replaced with decrypted content.
   
  
  
Known problems:
 - jQuery client side validation does not work. ( but form itself should work )


Version
----

1.0

Dependency
---
 - jQuery ( on which jCryption depends ) http://jquery.com/
 - jCryption 3.0.1 or later http://www.jcryption.org/
 - ASP.NET 4.0 or later
 - ( ASP.NET WebPages 2.0 or later )

Installation
---

 - App_Code/jCryption.cs
 - Scripts/jquery.jcryption.3.0.1.js
 

Integration Examples
---


####ASPX
Make ASPX page inherit jCryption.SecurePage. SecurePage handles the negotiations with jCryption client javascript library. Javascript initialization should be placed so that 'getKeysURL' and 'handshakeURL' can access the Page.

```aspx
<%@  Language="C#" Inherits="jCryption.SecurePage" %>
<html>
    <head>
		<script type="text/javascript" src="//ajax.googleapis.com/ajax/libs/jquery/2.0.3/jquery.min.js"></script>
		<script type="text/javascript" src="Scripts/jquery.jcryption.3.0.1.js"></script>
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

####CSHTML
 1. declare namespace access to 'jCryption' on the top of page.
 2. call jCryption.HandleRequest(Request) to handle all background negotiations.
 3. include all needed scripts ( jQuery and jCryption javascript files )
 3. call jCryption.RenderScriptFor("<jQuery selector for form>") in the page ( typically in head )
 


```cs
@using jCryption
@{
    jCryption.HandleRequest(Request);
}
<!doctype html>
<html>
<head>
    <script type="text/javascript" src="//ajax.googleapis.com/ajax/libs/jquery/2.0.3/jquery.min.js"></script>
    <script type="text/javascript" src="Scripts/jquery.jcryption.3.0.1.js"></script>
    @jCryption.RenderScriptFor("#normal")
</head>
......

```





License
----

MIT

[Jake Y.Yoshimura]: yo-ki@yo-ki.com
