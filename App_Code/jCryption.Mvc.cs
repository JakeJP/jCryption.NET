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