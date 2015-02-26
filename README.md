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
  - RSA keys are automatically generated on server side (no need of PEM file preparation)
  - Integration with ASPX, WebPages(cshtml) and MVC. Request.Form is automatically replaced with decrypted content.
  - Silently deactivates under HTTPS secure connection ( with cshtml helper methods )
  - load initial form data through encryption ( with CSHTML helper )
  - load encrypted HTML content rendering support (1.2)
  - Compatibility with jquery.validate
   
Suggestions for original jCryption
---
 - AESKey may be only one per page over multiple forms on the same page, since server-side holds only one key in the session state ( with the implementation of PHP ).
 - AESKey may be posted with encrypted form data together, which allows browser re-post form (by F5 refresh).
 - Server side handler should be neutral ( not bound to PHP, cgi, ASPX ). Url of server handlers are written hard coded in .js. Only one Server side end point should be supplied as an URL in an option parameter. 'handshake' 'getPublicKey' are its variants by query strings.
 - Handle form's submit event (not click). 'click' event occurs before form validation for example.
 - if AES key is attached to encrypted form post with 'jCryption'? This makes form post 'session' independent and allows form re-post by pressing F5.

jquery.jcryption.x.x.x.mod.js is the modified version which solves the problems above. mod version is also needed to work with MVC properly.

Dependency
---
 - jQuery ( on which jCryption depends ) http://jquery.com/
 - jCryption 3.0.1 or later http://www.jcryption.org/
 - ASP.NET 4.0 or later
 - ASP.NET WebPages 2.0 or later (option)
 - ASP.NET MVC 4 or later (option)

Installation
---
ASP.NET or ASP.NET WebPages
 - App_Code/jCryption.cs (ASP.NET and WebPages)
 - Scripts/jquery.jcryption.3.1.0.js ( or mod version )

ASP.NET MVC 4 or later
 - Filters/jCryption.cs [compile]
 - Filters/jCryption.Mvc.cs [compile]
 - Scripts/jquery.jcryption.3.1.0.mod.js
 

Integration Examples
---


##ASPX
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
##ASP.NET MVC
Place both `jCryption.cs` and `jCryption.Mvc.cs`  to be compiled in the project. They can be placed in any folder. Handshake and decryption are processed through jCryptionHandlerAttribute.

 - Decorate action methods that are potentially responsible to handle jCryption handshake and decryption with `[jCryptionHandler]` . The following example shows 2 Login methods must have `[jCryptionHandler]` attribute.

```cs
// GET: /Account/Login
[AllowAnonymous]
[jCryptionHandler]
public ActionResult Login(string returnUrl)
{ . . . }

// POST: /Account/Login
[HttpPost]
[AllowAnonymous]
[jCryptionHandler]
[ValidateAntiForgeryToken(Order=0)] // to make sure this action comes after jCryptionHandler
public ActionResult Login(LoginModel model, string returnUrl)
{ ... }
```

 - Include client side script in the form page.
```cs
@jCryption.RenderScriptFor("form",src:"/Scripts/jquery.jcryption.3.1.0.mod.js")
```

*mod version (jquery.jcryption.3.1.0.mod.js) is recommended to use with MVC, for some difficulties of SessionSate at simultaneous requests.*


###ASP.NET WebPages (cshtml)
 1. declare namespace access to 'jCryption' on the top of page.```@using jCryption```
 2. call ```jCryption.HandleRequest(Request)``` on the top of page to handle all background negotiations.
 3. include all depending scripts ( jQuery )
 4. call ```@jCryption.RenderScriptFor(...)``` in the page ( typically in head ). ( in the case with jquery validate, code should be placed after jquery.validate include. )

####@jCryption.RenderScriptFor( String selector, String src = null, String script = null )

 **selector**: jQuery selector to select 'form'
 **src**: javascript source to include. Usually an url to jquery.jcryption.xxx.js
 **script**: include a whole script block as HTML, <script src....>

 
```cs
@using jCryption
@{
    jCryption.HandleRequest(Request);
}
<!doctype html>
<html>
<head>
    <script type="text/javascript" src="//ajax.googleapis.com/ajax/libs/jquery/2.0.3/jquery.min.js"></script>
    @jCryption.RenderScriptFor("#form", src: "/Scripts/jquery.jcryption.3.1.0.js")
</head>
......
<form id="form">
.....
</form>
......

```

###Secure initial form data loading with cshtml page
jCryption provides a way to encrypt client to server data transfer but it does not protect form values that are initially rendered by server in a HTML form like ```<input name='Name' value='Smith' />```

This library provides some more methods to protect server to client transfered form data. 

####@jCryption.SecureNameValue( String name, String value )

is used to decorate name and value attributes in ```<input>```.

```html
<input type='text' @jCryption.SecureNameValue("Name", "Smith") />
```

####@jCryption.SecureNameValueCheck( String name, String value, bool check )
is used for checkbox and radio type input element.

```html
<input type='checkbox' @jCryption.SecureNameValueCheck("Animal", "Dog", true ) />
<input type='checkbox' @jCryption.SecureNameValueCheck("Animal", "Cat", false ) />
```

####~~@jCryption.RenderLoadFormData() [deleted]~~
####@jCryption.LoadSecureContents()
must be placed after all **SecureNameValue** function calls.
This renders a javascript block with encrypted form values, which are to be decrypted through server-client negotiation. Form elements are filled in javascript calls.

Version
----
#####1.3.3
 - added MVC support

#####1.3.2 update
 - updated jcryption.3.1.0.mod.js and examples

#####1.3.2
 - fix RenderScriptFor src, script parameter handling

#####1.3.1
 - fix for Unvalidated Form problem
 - add script parameter for RenderScript

#####1.3
 - Refactor of CSHTML helper functions

#####1.2
 - Encrypted HTML content rendering support (CSHTML)

#####1.1
 - jCryption version 3.1.0
 - secure form data loading ( on CSHTML )

#####1.0.1
 - now works with jquery.validate

#####1.0

License
----
Same as original jCryption,
MIT

[Jake Y.Yoshimura]: http://www.yo-ki.com/
