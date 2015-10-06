using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Web;
using System.Web.Security;
using System.Xml;
using dk.nita.saml20.Bindings;
using dk.nita.saml20.Identity;
using dk.nita.saml20.Session;
using dk.nita.saml20.identity;
using dk.nita.saml20.session;
using dk.nita.saml20.config;
using dk.nita.saml20.Logging;
using dk.nita.saml20.Properties;
using dk.nita.saml20.Schema.Metadata;
using dk.nita.saml20.Schema.Protocol;
using dk.nita.saml20.Utils;
using Saml2.Properties;
using Trace = dk.nita.saml20.Utils.Trace;
using dk.nita.saml20.Actions;

namespace dk.nita.saml20.protocol
{
    /// <summary>
    /// Handles logout for all SAML bindings.
    /// </summary>
    public class Saml20LogoutHandler : Saml20AbstractEndpointHandler
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20LogoutHandler"/> class.
        /// </summary>
        public Saml20LogoutHandler()
        {
            // Read the proper redirect url from config
            try
            {
                RedirectUrl = SAML20FederationConfig.GetConfig().ServiceProvider.LogoutEndpoint.RedirectUrl;
                ErrorBehaviour = SAML20FederationConfig.GetConfig().ServiceProvider.LogoutEndpoint.ErrorBehaviour.ToString();
            }
            catch (Exception e)
            {
                if (Trace.ShouldTrace(TraceEventType.Error))
                    Trace.TraceData(TraceEventType.Error, e.ToString());
            }
        }

        #region IHttpHandler related

        /// <summary>
        /// Handles a request.
        /// </summary>
        /// <param name="context">The context.</param>
        protected override void Handle(HttpContext context)
        {
            Trace.TraceMethodCalled(GetType(), "Handle()");

            try
            {
                //Some IdP's are known to fail to set an actual value in the SOAPAction header
                //so we just check for the existence of the header field.
                if (Array.Exists(context.Request.Headers.AllKeys, delegate(string s) { return s == SOAPConstants.SOAPAction; }))
                {
                    HandleSOAP(context, context.Request.InputStream);
                    return;
                }

                if (!string.IsNullOrEmpty(context.Request.Params["SAMLart"]))
                {
                    HandleArtifact(context);
                    return;
                }

                if (!string.IsNullOrEmpty(context.Request.Params["SAMLResponse"]))
                {
                    HandleResponse(context);
                }
                else if (!string.IsNullOrEmpty(context.Request.Params["SAMLRequest"]))
                {
                    HandleRequest(context);
                }
                else
                {
                    IDPEndPoint idpEndpoint = null;
                    Saml20AssertionLite saml20AssertionLite = Saml20PrincipalCache.GetSaml20AssertionLite();
                    if (saml20AssertionLite != null)
                    {
                        idpEndpoint = RetrieveIDPConfiguration(saml20AssertionLite.Issuer);
                    }

                    if (idpEndpoint == null)
                    {
                        context.User = null;
                        FormsAuthentication.SignOut();
                        HandleError(context, Resources.UnknownLoginIDP);
                    }

                    TransferClient(idpEndpoint, context);
                }
            }
            catch (Exception e)
            {
                //ThreadAbortException is thrown by response.Redirect so don't worry about it
                if (e is ThreadAbortException)
                    throw;

                HandleError(context, e.Message);
            }
        }

        #endregion

        #region SP Initiated logout

        private void HandleArtifact(HttpContext context)
        {
            HttpArtifactBindingBuilder builder = new HttpArtifactBindingBuilder(context);
            Stream inputStream = builder.ResolveArtifact();

            HandleSOAP(context, inputStream);
        }

        private void HandleSOAP(HttpContext context, Stream inputStream)
        {
            Trace.TraceMethodCalled(GetType(), "HandleSOAP");

            HttpArtifactBindingParser parser = new HttpArtifactBindingParser(inputStream);
            HttpArtifactBindingBuilder builder = new HttpArtifactBindingBuilder(context);
            SAML20FederationConfig config = SAML20FederationConfig.GetConfig();

            IDPEndPoint idp = RetrieveIDPConfiguration(parser.Issuer);
            AuditLogging.IdpId = idp.Id;


            if (parser.IsArtifactResolve())
            {
                Trace.TraceData(TraceEventType.Information, Tracing.ArtifactResolveIn);

                if (!parser.CheckSamlMessageSignature(idp.metadata.Keys))
                {
                    HandleError(context, "Invalid Saml message signature");
                    AuditLogging.logEntry(Direction.UNDEFINED, Operation.ARTIFACTRESOLVE, "Signature could not be verified", parser.SamlMessage);
                }
                AuditLogging.AssertionId = parser.ArtifactResolve.ID;
                AuditLogging.logEntry(Direction.IN, Operation.ARTIFACTRESOLVE, "", parser.SamlMessage);
                builder.RespondToArtifactResolve(parser.ArtifactResolve);
            }
            else if (parser.IsArtifactResponse())
            {
                Trace.TraceData(TraceEventType.Information, Tracing.ArtifactResponseIn);

                Status status = parser.ArtifactResponse.Status;
                if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
                {
                    AuditLogging.logEntry(Direction.UNDEFINED, Operation.ARTIFACTRESOLVE, string.Format("Unexpected status code for artifact response: {0}, expected 'Success', msg: {1}", status.StatusCode.Value, parser.SamlMessage));
                    HandleError(context, status);
                    return;
                }

                if (parser.ArtifactResponse.Any.LocalName == LogoutRequest.ELEMENT_NAME)
                {
                    if (Trace.ShouldTrace(TraceEventType.Information))
                        Trace.TraceData(TraceEventType.Information, string.Format(Tracing.LogoutRequest, parser.ArtifactResponse.Any.OuterXml));

                    //Send logoutresponse via artifact
                    Saml20LogoutResponse response = new Saml20LogoutResponse();
                    response.Issuer = config.ServiceProvider.ID;
                    LogoutRequest req = Serialization.DeserializeFromXmlString<LogoutRequest>(parser.ArtifactResponse.Any.OuterXml);
                    response.StatusCode = Saml20Constants.StatusCodes.Success;
                    response.InResponseTo = req.ID;
                    Saml20AssertionLite saml20AssertionLite = Saml20PrincipalCache.GetSaml20AssertionLite();
                    IDPEndPoint endpoint = RetrieveIDPConfiguration(saml20AssertionLite.Issuer);
                    IDPEndPointElement destination =
                        DetermineEndpointConfiguration(SAMLBinding.REDIRECT, endpoint.SLOEndpoint, endpoint.metadata.SLOEndpoints());

                    builder.RedirectFromLogout(destination, response);
                }
                else if (parser.ArtifactResponse.Any.LocalName == LogoutResponse.ELEMENT_NAME)
                {
                    DoLogout(context);
                }
                else
                {
                    AuditLogging.logEntry(Direction.UNDEFINED, Operation.ARTIFACTRESOLVE, string.Format("Unsupported payload message in ArtifactResponse: {0}, msg: {1}", parser.ArtifactResponse.Any.LocalName, parser.SamlMessage));
                    HandleError(context,
                                string.Format("Unsupported payload message in ArtifactResponse: {0}",
                                              parser.ArtifactResponse.Any.LocalName));
                }
            }
            else if (parser.IsLogoutReqest())
            {
                if (Trace.ShouldTrace(TraceEventType.Information))
                    Trace.TraceData(TraceEventType.Information, string.Format(Tracing.LogoutRequest, parser.SamlMessage.OuterXml));

                Saml20LogoutResponse response = new Saml20LogoutResponse();

                if (!parser.IsSigned())
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, "Signature not present in SOAP logout request, msg: " + parser.SamlMessage.OuterXml);
                    response.StatusCode = Saml20Constants.StatusCodes.RequestDenied;
                }

                if (idp.metadata == null)
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, "Cannot find metadata for IdP: " + parser.Issuer);
                    // Not able to process the request as we do not know the IdP.
                    response.StatusCode = Saml20Constants.StatusCodes.NoAvailableIDP;
                }
                else
                {
                    Saml20MetadataDocument metadata = idp.metadata;

                    if (!parser.CheckSignature(metadata.GetKeys(KeyTypes.signing)))
                    {
                        AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, "Request has been denied. Invalid signature SOAP logout, msg: " + parser.SamlMessage.OuterXml);
                        response.StatusCode = Saml20Constants.StatusCodes.RequestDenied;
                    }
                }

                if (parser.GetNameID() != null && !string.IsNullOrEmpty(parser.GetNameID().Value))
                    DoSoapLogout(context, parser.GetNameID().Value);
                else
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, "Request has been denied. No user ID was supplied in SOAP logout request, msg: " + parser.SamlMessage.OuterXml);
                    response.StatusCode = Saml20Constants.StatusCodes.NoAuthnContext;
                }

                LogoutRequest req = parser.LogoutRequest;

                //Build the response object
                response.Issuer = config.ServiceProvider.ID;
                response.StatusCode = Saml20Constants.StatusCodes.Success;
                response.InResponseTo = req.ID;
                XmlDocument doc = response.GetXml();
                XmlSignatureUtils.SignDocument(doc, response.ID);
                if (doc.FirstChild is XmlDeclaration)
                    doc.RemoveChild(doc.FirstChild);

                builder.SendResponseMessage(doc.OuterXml);

            }
            else
            {
                Status s = parser.GetStatus();
                if (s != null)
                {
                    HandleError(context, s);
                }
                else
                {
                    AuditLogging.logEntry(Direction.UNDEFINED, Operation.ARTIFACTRESOLVE, string.Format("Unsupported SamlMessage element: {0}, msg: {1}", parser.SamlMessageName, parser.SamlMessage));
                    HandleError(context, string.Format("Unsupported SamlMessage element: {0}", parser.SamlMessageName));
                }
            }
        }


        private void TransferClient(IDPEndPoint endpoint, HttpContext context)
        {
            Trace.TraceMethodCalled(GetType(), "TransferClient()");

            Saml20LogoutRequest request = Saml20LogoutRequest.GetDefault();

            AuditLogging.AssertionId = request.ID;
            AuditLogging.IdpId = endpoint.Id;

            // Determine which endpoint to use from the configuration file or the endpoint metadata.
            IDPEndPointElement destination =
                DetermineEndpointConfiguration(SAMLBinding.REDIRECT, endpoint.SLOEndpoint, endpoint.metadata.SLOEndpoints());

            request.Destination = destination.Url;

            request.SubjectToLogOut.Format = Saml20PrincipalCache.GetSaml20AssertionLite().Subject.Format;

            if (destination.Binding == SAMLBinding.POST)
            {
                HttpPostBindingBuilder builder = new HttpPostBindingBuilder(destination);
                request.Destination = destination.Url;
                request.Reason = Saml20Constants.Reasons.User;
                request.SubjectToLogOut.Value = Saml20PrincipalCache.GetSaml20AssertionLite().Subject.Value;
                request.SessionIndex = Saml20PrincipalCache.GetSaml20AssertionLite().SessionIndex;
                XmlDocument requestDocument = request.GetXml();
                XmlSignatureUtils.SignDocument(requestDocument, request.ID);
                builder.Request = requestDocument.OuterXml;

                if (Trace.ShouldTrace(TraceEventType.Information))
                    Trace.TraceData(TraceEventType.Information, string.Format(Tracing.SendLogoutRequest, "POST", endpoint.Id, requestDocument.OuterXml));

                AuditLogging.logEntry(Direction.OUT, Operation.LOGOUTREQUEST, "Binding: POST");
                builder.GetPage().ProcessRequest(context);
                context.Response.End();
                return;
            }

            if (destination.Binding == SAMLBinding.REDIRECT)
            {
                HttpRedirectBindingBuilder builder = new HttpRedirectBindingBuilder();
                builder.signingKey = FederationConfig.GetConfig().SigningCertificate.GetCertificate().PrivateKey;
                request.Destination = destination.Url;
                request.Reason = Saml20Constants.Reasons.User;
                request.SubjectToLogOut.Value = Saml20PrincipalCache.GetSaml20AssertionLite().Subject.Value;
                request.SessionIndex = Saml20PrincipalCache.GetSaml20AssertionLite().SessionIndex;
                builder.Request = request.GetXml().OuterXml;

                string redirectUrl = destination.Url + "?" + builder.ToQuery();

                if (Trace.ShouldTrace(TraceEventType.Information))
                    Trace.TraceData(TraceEventType.Information, string.Format(Tracing.SendLogoutRequest, "REDIRECT", endpoint.Id, redirectUrl));

                AuditLogging.logEntry(Direction.OUT, Operation.LOGOUTREQUEST, "Binding: Redirect");
                context.Response.Redirect(redirectUrl, true);
                return;
            }

            if (destination.Binding == SAMLBinding.ARTIFACT)
            {
                if (Trace.ShouldTrace(TraceEventType.Information))
                    Trace.TraceData(TraceEventType.Information, string.Format(Tracing.SendLogoutRequest, "ARTIFACT", endpoint.Id, string.Empty));

                request.Destination = destination.Url;
                request.Reason = Saml20Constants.Reasons.User;
                request.SubjectToLogOut.Value = Saml20PrincipalCache.GetSaml20AssertionLite().Subject.Value;
                request.SessionIndex = Saml20PrincipalCache.GetSaml20AssertionLite().SessionIndex;

                HttpArtifactBindingBuilder builder = new HttpArtifactBindingBuilder(context);
                AuditLogging.logEntry(Direction.OUT, Operation.LOGOUTREQUEST, "Method: Artifact");
                builder.RedirectFromLogout(destination, request, Guid.NewGuid().ToString("N"));
            }

            HandleError(context, Resources.BindingError);
        }

        #endregion

        #region SAMLResponse related

        private void HandleResponse(HttpContext context)
        {
            Trace.TraceMethodCalled(GetType(), "HandleResponse()");


            string message = string.Empty;

            if (context.Request.RequestType == "GET")
            {
                HttpRedirectBindingParser parser = new HttpRedirectBindingParser(context.Request.Url);
                LogoutResponse response = Serialization.DeserializeFromXmlString<LogoutResponse>(parser.Message);

                AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE,
                                      string.Format("Binding: redirect, Signature algorithm: {0}  Signature:  {1}, Message: {2}", parser.SignatureAlgorithm, parser.Signature, parser.Message));

                IDPEndPoint idp = RetrieveIDPConfiguration(response.Issuer.Value);

                AuditLogging.IdpId = idp.Id;
                AuditLogging.AssertionId = response.ID;

                if (idp.metadata == null)
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE,
                                      string.Format("No IDP metadata, unknown IDP, response: {0}", parser.Message));
                    HandleError(context, Resources.UnknownIDP);
                    return;
                }

                if (!parser.VerifySignature(idp.metadata.Keys))
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE,
                                      string.Format("Invalid signature in redirect-binding, response: {0}", parser.Message));
                    HandleError(context, Resources.SignatureInvalid);
                    return;
                }

                message = parser.Message;
            }
            else if (context.Request.RequestType == "POST")
            {
                HttpPostBindingParser parser = new HttpPostBindingParser(context);
                AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE,
                                      "Binding: POST, Message: " + parser.Message);


                LogoutResponse response = Serialization.DeserializeFromXmlString<LogoutResponse>(parser.Message);

                IDPEndPoint idp = RetrieveIDPConfiguration(response.Issuer.Value);

                if (idp.metadata == null)
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE,
                                      string.Format("No IDP metadata, unknown IDP, response: {0}", parser.Message));
                    HandleError(context, Resources.UnknownIDP);
                    return;
                }

                if (!parser.IsSigned())
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE,
                                      string.Format("Signature not present, response: {0}", parser.Message));
                    HandleError(context, Resources.SignatureNotPresent);
                }

                // signature on final message in logout
                if (!parser.CheckSignature(idp.metadata.Keys))
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE,
                                      string.Format("Invalid signature in post-binding, response: {0}", parser.Message));
                    HandleError(context, Resources.SignatureInvalid);
                }

                message = parser.Message;
            }
            else
            {
                AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE,
                                      string.Format("Unsupported request type format, type: {0}", context.Request.RequestType));
                HandleError(context, Resources.UnsupportedRequestTypeFormat(context.Request.RequestType));
            }

            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = null;
            doc.PreserveWhitespace = true;
            doc.LoadXml(message);

            XmlElement statElem =
                (XmlElement)doc.GetElementsByTagName(Status.ELEMENT_NAME, Saml20Constants.PROTOCOL)[0];

            Status status = Serialization.DeserializeFromXmlString<Status>(statElem.OuterXml);

            if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
            {
                AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE,
                                      string.Format("Unexpected status code: {0}, msg: {1}", status.StatusCode.Value, message));
                HandleError(context, status);
                return;
            }

            AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE,
                     "Assertion validated succesfully");

            //Log the user out locally
            DoLogout(context);
        }

        #endregion

        #region SAMLRequest related

        private void HandleRequest(HttpContext context)
        {
            Trace.TraceMethodCalled(GetType(), "HandleRequest()");

            //Fetch config object
            SAML20FederationConfig config = SAML20FederationConfig.GetConfig();

            LogoutRequest logoutRequest = null;
            IDPEndPoint endpoint = null;
            string message = string.Empty;

            //Build the response object
            var response = new Saml20LogoutResponse();
            response.Issuer = config.ServiceProvider.ID;
            response.StatusCode = Saml20Constants.StatusCodes.Success; // Default success. Is overwritten if something fails.

            if (context.Request.RequestType == "GET") // HTTP Redirect binding
            {
                HttpRedirectBindingParser parser = new HttpRedirectBindingParser(context.Request.Url);
                AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST,
                                      string.Format("Binding: redirect, Signature algorithm: {0}  Signature:  {1}, Message: {2}", parser.SignatureAlgorithm, parser.Signature, parser.Message));

                if (!parser.IsSigned)
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, "Signature not present, msg: " + parser.Message);
                    response.StatusCode = Saml20Constants.StatusCodes.RequestDenied;
                }

                logoutRequest = parser.LogoutRequest;
                endpoint = config.FindEndPoint(logoutRequest.Issuer.Value);

                if (endpoint.metadata == null)
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, "Cannot find metadata for IdP: " + logoutRequest.Issuer.Value);
                    // Not able to return a response as we do not know the IdP.
                    HandleError(context, "Cannot find metadata for IdP " + logoutRequest.Issuer.Value);
                    return;
                }

                Saml20MetadataDocument metadata = endpoint.metadata;

                if (!parser.VerifySignature(metadata.GetKeys(KeyTypes.signing)))
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, "Request has been denied. Invalid signature redirect-binding, msg: " + parser.Message);
                    response.StatusCode = Saml20Constants.StatusCodes.RequestDenied;
                }

                message = parser.Message;
            }
            else if (context.Request.RequestType == "POST") // HTTP Post binding
            {
                HttpPostBindingParser parser = new HttpPostBindingParser(context);
                AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST,
                                      "Binding: POST, Message: " + parser.Message);

                if (!parser.IsSigned())
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, "Signature not present, msg: " + parser.Message);
                    response.StatusCode = Saml20Constants.StatusCodes.RequestDenied;
                }

                logoutRequest = parser.LogoutRequest;
                endpoint = config.FindEndPoint(logoutRequest.Issuer.Value);
                if (endpoint.metadata == null)
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, "Cannot find metadata for IdP");
                    // Not able to return a response as we do not know the IdP.
                    HandleError(context, "Cannot find metadata for IdP " + logoutRequest.Issuer.Value);
                    return;
                }

                Saml20MetadataDocument metadata = endpoint.metadata;

                // handle a logout-request
                if (!parser.CheckSignature(metadata.GetKeys(KeyTypes.signing)))
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, "Request has been denied. Invalid signature post-binding, msg: " + parser.Message);
                    response.StatusCode = Saml20Constants.StatusCodes.RequestDenied;
                }

                message = parser.Message;
            }
            else
            {
                //Error: We don't support HEAD, PUT, CONNECT, TRACE, DELETE and OPTIONS
                // Not able to return a response as we do not understand the request.
                HandleError(context, Resources.UnsupportedRequestTypeFormat(context.Request.RequestType));
            }

            AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, message);

            // Check that idp in session and request matches.
            string idpRequest = logoutRequest.Issuer.Value;
            
            // SessionFactory.SessionContext.Current.New is never the first call to Current due to the logic in Application_AuthenticateRequest() ... Saml20Identity.IsInitialized()
            // Hence we need to check on Saml20Identity.IsInitialized() instead of using SessionFactory.SessionContext.Current.New.
            bool isOioSamlSessionActive = Saml20Identity.IsInitialized();
            if (isOioSamlSessionActive)
            {
                object idpId = Saml20PrincipalCache.GetSaml20AssertionLite().Issuer;

                if (idpId != null && idpId.ToString() != idpRequest)
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, Resources.IdPMismatchBetweenRequestAndSessionFormat(idpId, idpRequest), message);
                    response.StatusCode = Saml20Constants.StatusCodes.RequestDenied;
                }
            }
            else
            {
                // All other status codes than Success results in the IdP throwing an error page. Therefore we return default Success even if we do not have a session.
                AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, "Session does not exist. Continues the redirect logout procedure with status code success." + idpRequest, message);
            }

            //  Only logout if request is valid and we are working on an existing Session.
            if (Saml20Constants.StatusCodes.Success == response.StatusCode && isOioSamlSessionActive)
            {
                // Execute all actions that the service provider has configured
                DoLogout(context, true);
            }

            // Update the response object with informations that first is available when request has been parsed.
            IDPEndPointElement destination = DetermineEndpointConfiguration(SAMLBinding.REDIRECT, endpoint.SLOEndpoint, endpoint.metadata.SLOEndpoints());
            response.Destination = destination.Url;
            response.InResponseTo = logoutRequest.ID;

            //Respond using redirect binding
            if (destination.Binding == SAMLBinding.REDIRECT)
            {
                HttpRedirectBindingBuilder builder = new HttpRedirectBindingBuilder();
                builder.RelayState = context.Request.Params["RelayState"];
                builder.Response = response.GetXml().OuterXml;
                builder.signingKey = FederationConfig.GetConfig().SigningCertificate.GetCertificate().PrivateKey;
                string s = destination.Url + "?" + builder.ToQuery();
                context.Response.Redirect(s, true);
                return;
            }

            //Respond using post binding
            if (destination.Binding == SAMLBinding.POST)
            {
                HttpPostBindingBuilder builder = new HttpPostBindingBuilder(destination);
                builder.Action = SAMLAction.SAMLResponse;
                XmlDocument responseDocument = response.GetXml();
                XmlSignatureUtils.SignDocument(responseDocument, response.ID);
                builder.Response = responseDocument.OuterXml;
                builder.RelayState = context.Request.Params["RelayState"];
                builder.GetPage().ProcessRequest(context);
                return;
            }
        }

        #endregion

        #region Private utility functions

        private void DoLogout(HttpContext context)
        {
            DoLogout(context, false);
        }

        private void DoLogout(HttpContext context, bool IdPInitiated)
        {

            try
            {
                foreach (IAction action in Actions.Actions.GetActions())
                {
                    Trace.TraceMethodCalled(action.GetType(), "LogoutAction()");

                    action.LogoutAction(this, context, IdPInitiated);

                    Trace.TraceMethodDone(action.GetType(), "LogoutAction()");
                }
            }
            finally
            {
                // Always end with abandoning the session.
                Trace.TraceData(TraceEventType.Information, "Clearing session with id: " + SessionFactory.SessionContext.Current.Id);
                SessionFactory.SessionContext.AbandonAllSessions(Saml20Identity.Current.Name);
                //SessionFactory.SessionContext.AbandonCurrentSession();
                Trace.TraceData(TraceEventType.Verbose, "Session cleared.");
            }
        }

        private void DoSoapLogout(HttpContext context, string userId)
        {
            try
            {
                foreach (IAction action in Actions.Actions.GetActions())
                {
                    Trace.TraceMethodCalled(action.GetType(), "SoapLogoutAction()");

                    action.SoapLogoutAction(this, context, userId);

                    Trace.TraceMethodDone(action.GetType(), "SoapLogoutAction()");
                }
            }
            finally
            {
                // Always end with abandoning the session.
                Trace.TraceData(TraceEventType.Information, "Clearing all sessions related to user with id: " + userId);
                SessionFactory.SessionContext.AbandonAllSessions(userId);
                Trace.TraceData(TraceEventType.Verbose, "Sessions cleared.");
            }
        }

        #endregion
    }
}
