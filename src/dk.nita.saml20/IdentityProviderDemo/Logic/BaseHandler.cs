using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Web;
using System.Web.SessionState;
using System.Xml;
using dk.nita.saml20;
using dk.nita.saml20.Bindings;
using dk.nita.saml20.config;
using dk.nita.saml20.Schema.Metadata;
using dk.nita.saml20.Utils;

namespace IdentityProviderDemo.Logic
{
    public abstract class BaseHandler : IHttpHandler, IRequiresSessionState 
    {
        public abstract void ProcessRequest(HttpContext context);

        /// <summary>
        /// Retrieves the metadata of the federation partner with the given id.
        /// </summary>
        /// <param name="SPID"></param>
        /// <returns></returns>
        protected static Saml20MetadataDocument GetMetadata(string SPID)
        {
            Saml20MetadataDocument result = IDPConfig.GetServiceProviderMetadata(SPID);
            if (result == null)            
                handleUnknownServiceProvider(SPID); // Response.End() called. Won't return.         

            return result;
        }

        public bool IsReusable { 
            get { return false; } 
        }

        /// <summary>
        /// Checks the signature of a message received using the redirect binding using the keys found in the 
        /// metadata of the federation partner that sent the request.
        /// </summary>
        protected static bool CheckRedirectSignature(HttpRedirectBindingParser parser, Saml20MetadataDocument metadata)
        {
            List<KeyDescriptor> keys = metadata.GetKeys(KeyTypes.signing);
            // Go through the list of signing keys (usually only one) and use it to verify the REDIRECT request.
            foreach (KeyDescriptor key in keys)
            {
                KeyInfo keyinfo = (KeyInfo)key.KeyInfo;
                foreach (KeyInfoClause keyInfoClause in keyinfo)
                {
                    AsymmetricAlgorithm signatureKey = XmlSignatureUtils.ExtractKey(keyInfoClause);
                    if (signatureKey != null && parser.CheckSignature(signatureKey))
                        return true;                    
                }
            }
            return false;
        }

        protected static void HandleUnableToVerifySignature(string SPID)
        {
            HttpContext.Current.Response.Write(string.Format("Unable to verify the signature of request from '{0}'.", SPID));
            HttpContext.Current.Response.End();            
        }

        protected static void handleUnknownServiceProvider(string SPID)
        {
            HttpContext.Current.Response.Write(string.Format("The service provider '{0}' is not recognized.", SPID));
            HttpContext.Current.Response.End();            
        }

        /// <summary>
        /// Transfers the message to the given endpoint using the HTTP-Redirect binding.
        /// </summary>
        protected static void HTTPRedirect(SAMLAction action, IDPEndPointElement endpoint, XmlNode message)
        {
            if (message.FirstChild is XmlDeclaration)
                message.RemoveChild(message.FirstChild);

            HttpRedirectBindingBuilder builder = new HttpRedirectBindingBuilder();

            if (action == SAMLAction.SAMLRequest)
                builder.Request = message.OuterXml;
            else
                builder.Response = message.OuterXml;

            builder.signingKey = IDPConfig.IDPCertificate.PrivateKey;

            UriBuilder url = new UriBuilder(endpoint.Url);
            url.Query = builder.ToQuery();

            HttpContext.Current.Response.Redirect(url.ToString(), true);                        
        }
    }
}
