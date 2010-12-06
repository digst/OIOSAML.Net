using System;
using System.Collections.Generic;
using System.Web;
using System.IO;
using dk.nita.saml20;
using dk.nita.saml20.config;
using dk.nita.saml20.protocol;
using IdentityProviderDemo.config;
using IdentityProviderDemo.Logic;
using dk.nita.saml20.Bindings;
using dk.nita.saml20.Schema.Protocol;
using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.Utils;

namespace IdentityProviderDemo
{
    /// <summary>
    /// Handles SLO.
    /// </summary>
    public class LogoutHandler : BaseHandler 
    {
        private const string LOGOUTINITIATORKEY = "IdentityProviderDemo.LogoutInitiator";

        /// <summary>
        /// Processes the request.
        /// </summary>
        /// <param name="context">The context.</param>
        public override void ProcessRequest(HttpContext context)
        {
            if (context.Request.HttpMethod != "GET")
                return; // Only handle Redirect logouts.

            HttpRedirectBindingParser parser = new HttpRedirectBindingParser(context.Request.Url);
            if (context.Request.Params["SAMLRequest"] != null)
            {                
                HandleLogoutRequest(parser);
            }

            if (context.Request.Params["SAMLResponse"] != null)
            {
                HandleLogoutResponse(parser);
            }
        }

        private static void HandleLogoutRequest(HttpRedirectBindingParser parser)
        {
            LogoutRequest req = Serialization.DeserializeFromXmlString<LogoutRequest>(parser.Message);

            // Retrieve metadata of requestor.
            string SPID = req.Issuer.Value;
            Saml20MetadataDocument SPmetadata = GetMetadata(SPID);

            if (parser.IsSigned && !CheckRedirectSignature(parser, SPmetadata))
            {
                HandleUnableToVerifySignature(SPID);
                return;
            }

            // Set the entity ID of the federation partner that initiated the logout.
            HttpContext.Current.Session[LOGOUTINITIATORKEY] = SPID;
            UserSessionsHandler.RemoveLoggedInSession(SPID);

            Logout();
        }

        private static void HandleLogoutResponse(HttpRedirectBindingParser parser)
        {
            LogoutResponse res = Serialization.DeserializeFromXmlString<LogoutResponse>(parser.Message);

            // Retrieve metadata of requestor.
            string SPID = res.Issuer.Value;
            Saml20MetadataDocument SPmetadata = GetMetadata(SPID);

            if (parser.IsSigned && !CheckRedirectSignature(parser, SPmetadata))
            {
                HandleUnableToVerifySignature(SPID);
                return;
            }

            // Remove the Service Provider from the list of the user's active sessions.
            UserSessionsHandler.RemoveLoggedInSession(SPID);

            Logout();
        }

        /// <summary>
        /// Initiate logout.
        /// </summary>
        private static void Logout()
        {
            List<string> sessions = UserSessionsHandler.GetLoggedInSessions();
            
            if (sessions.Count > 0)
            {
                // Retrieve the next entity id and initiate logout.
                string entityId = sessions[0];
                UserSessionsHandler.RemoveLoggedInSession(entityId);
                CreateLogoutRequest(entityId);
            } else
            {
                // No more active sessions. Send a LogoutResponse to the service provider that initiated the Logout.
                string initiatingEntity = (string) HttpContext.Current.Session[LOGOUTINITIATORKEY];
                HttpContext.Current.Session.Remove(LOGOUTINITIATORKEY);

                UserSessionsHandler.DestroySession();
                CreateLogoutResponse(initiatingEntity);
            }

        }

        /// <summary>
        /// Build a LogoutResponse and send it to the federation partner with the given entity ID.
        /// </summary>
        /// <param name="entityID"></param>
        private static void CreateLogoutResponse(string entityID)
        {
            Saml20MetadataDocument metadata = GetMetadata(entityID);

            //IDPEndPointElement endpoint = metadata.SLOEndpoint(SAMLBinding.REDIRECT);
            IDPEndPointElement endpoint = metadata.SLOEndpoint(SAMLBinding.POST);

            Saml20LogoutResponse response = new Saml20LogoutResponse();
            response.Issuer = IDPConfig.ServerBaseUrl;
            response.Destination = endpoint.Url;
            response.StatusCode = Saml20Constants.StatusCodes.Success;

            HTTPRedirect(SAMLAction.SAMLResponse, endpoint, response.GetXml());
        }

        /// <summary>
        /// Build a LogoutRequest and send it to the Federation Partner with the given entity ID.
        /// </summary>
        /// <param name="entityID"></param>
        private static void CreateLogoutRequest(string entityID)
        {
            User user = UserSessionsHandler.CurrentUser;                        

            Saml20LogoutRequest request = new Saml20LogoutRequest();
            request.Issuer = IDPConfig.ServerBaseUrl;
            request.SessionIndex = Guid.NewGuid().ToString("N");
           
            request.SubjectToLogOut = new NameID();
            request.SubjectToLogOut.Format = Saml20Constants.NameIdentifierFormats.Unspecified;
            request.SubjectToLogOut.Value = user.Username;

            Saml20MetadataDocument metadata = GetMetadata(entityID);
            
            // HTTPRedirect(SAMLAction.SAMLRequest, metadata.SLOEndpoint(SAMLBinding.REDIRECT), request.GetXml());


            HttpPostBindingBuilder builder = new HttpPostBindingBuilder(metadata.SLOEndpoint(SAMLBinding.POST));
            builder.Action = SAMLAction.SAMLRequest;
            //builder.Response = assertionDoc.OuterXml;

            string xmloutput = request.GetXml().OuterXml;

            TextWriter tw = new StreamWriter("C:\\temp\\idp.txt", true);
            tw.WriteLine(xmloutput);
            tw.Close();

            builder.Response = xmloutput;

            builder.GetPage().ProcessRequest(HttpContext.Current);
            HttpContext.Current.Response.End();
        }
    }
}
