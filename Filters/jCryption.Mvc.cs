/*
 * jCryption.NET v 1.3.3
 * additional compornent for MVC
 * https://github.com/JakeJP/jCryption.NET
 * MIT license.
 * http://www.opensource.org/licenses/mit-license.php
 * 
 * jCryption client side library is originally created by Daniel Griesser:
 * http://www.jcryption.org/
 * 
 */
using System;
using System.Web.Mvc;
namespace jCryption
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
    public class jCryptionHandlerAttribute : FilterAttribute, IAuthorizationFilter
    {
        public void OnAuthorization(AuthorizationContext filterContext)
        {
            jCryption.HandleRequest(filterContext.HttpContext.Request);
        }
    }
}