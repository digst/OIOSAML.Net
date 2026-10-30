using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Linq;
using System.Web;
using System.Web.Caching;
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
using dk.nita.saml20.Bindings.SignatureProviders;

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
                if (Array.Exists(context.Request.Headers.AllKeys, delegate (string s) { return s == SOAPConstants.SOAPAction; }))
                {
                    HandleSOAP(context, context.Request.InputStream, null);
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

            Stream inputStream = builder.ResolveArtifact(out var artifactResolveId);

            HandleSOAP(context, inputStream, artifactResolveId);
        }

        /// <summary>
        /// Handles a SOAP message: a request received over SOAP, or the response to an ArtifactResolve sent by this service provider.
        /// </summary>
        /// <param name="context">The current HTTP context.</param>
        /// <param name="inputStream">The SOAP message.</param>
        /// <param name="artifactResolveId">The ID of the ArtifactResolve this service provider sent, when the message is its response; null for a request received over SOAP.</param>
        private void HandleSOAP(HttpContext context, Stream inputStream, string artifactResolveId)
        {
            Trace.TraceMethodCalled(GetType(), "HandleSOAP");

            HttpArtifactBindingParser parser = new HttpArtifactBindingParser(inputStream);
            HttpArtifactBindingBuilder builder = new HttpArtifactBindingBuilder(context);

            SAML20FederationConfig config = SAML20FederationConfig.GetConfig();

            IDPEndPoint idp = RetrieveIDPConfiguration(parser.Issuer);
            var shaHashingAlgorithm = SignatureProviderFactory.ValidateShaHashingAlgorithm(idp.ShaHashingAlgorithm);
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
                builder.RespondToArtifactResolve(idp, parser.ArtifactResolve);
            }
            else if (parser.IsArtifactResponse())
            {
                Trace.TraceData(TraceEventType.Information, Tracing.ArtifactResponseIn);

                // Only accept an ArtifactResponse as the response to an ArtifactResolve sent by this service provider.
                if (!AnswersArtifactResolve(artifactResolveId, parser.ArtifactResponse.InResponseTo))
                {
                    AuditLogging.logEntry(Direction.IN, Operation.ARTIFACTRESOLVE, "ArtifactResponse rejected: " + Resources.UnexpectedArtifactResponse);
                    HandleError(context, Resources.UnexpectedArtifactResponse);
                    return;
                }

                Status status = parser.ArtifactResponse.Status;
                if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
                {
                    AuditLogging.logEntry(Direction.UNDEFINED, Operation.ARTIFACTRESOLVE, string.Format("Unexpected status code for artifact response: {0}, expected 'Success', msg: {1}", status.StatusCode.Value, LogText.Describe(parser.SamlMessage)));
                    HandleError(context, status);
                    return;
                }

                if (parser.ArtifactResponse.Any.LocalName == LogoutRequest.ELEMENT_NAME)
                {
                    if (Trace.ShouldTrace(TraceEventType.Verbose))
                        Trace.TraceData(TraceEventType.Verbose, string.Format(Tracing.LogoutRequest, parser.ArtifactResponse.Any.OuterXml));

                    //Send logoutresponse via artifact
                    Saml20LogoutResponse response = new Saml20LogoutResponse();
                    response.Issuer = config.ServiceProvider.ID;
                    LogoutRequest req = Serialization.DeserializeFromXmlString<LogoutRequest>(parser.ArtifactResponse.Any.OuterXml);
                    response.StatusCode = Saml20Constants.StatusCodes.Success;
                    response.InResponseTo = req.ID;

                    // The artifact was resolved over TLS, so the request needs no signature of its own, but it must come from the IdP that answered.
                    if (req.Issuer?.Value != idp.Id)
                    {
                        AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, "Request has been denied. The LogoutRequest is not issued by the IdP that sent the ArtifactResponse");
                        Deny(response);
                    }
                    else
                    {
                        ProcessLogoutRequest(context, req, idp, false, response);
                    }

                    IDPEndPointElement destination =
                        DetermineEndpointConfiguration(SAMLBinding.REDIRECT, idp.SLOEndpoint, idp.metadata.SLOEndpoints());

                    builder.RedirectFromLogout(idp, destination, response);
                }
                else if (parser.ArtifactResponse.Any.LocalName == LogoutResponse.ELEMENT_NAME)
                {
                    FinishLogout(context, Serialization.DeserializeFromXmlString<LogoutResponse>(parser.ArtifactResponse.Any.OuterXml), false);
                }
                else
                {
                    AuditLogging.logEntry(Direction.UNDEFINED, Operation.ARTIFACTRESOLVE, string.Format("Unsupported payload message in ArtifactResponse: {0}, msg: {1}", parser.ArtifactResponse.Any.LocalName, LogText.Describe(parser.SamlMessage)));
                    HandleError(context,"Unsupported payload message in ArtifactResponse: {0}", parser.ArtifactResponse.Any.LocalName);
                }
            }
            else if (parser.IsLogoutReqest())
            {
                if (Trace.ShouldTrace(TraceEventType.Verbose))
                    Trace.TraceData(TraceEventType.Verbose, string.Format(Tracing.LogoutRequest, parser.SamlMessage.OuterXml));

                Saml20LogoutResponse response = new Saml20LogoutResponse();

                var (statusCode, subStatusCode) = HandleSoapLogoutRequest(
                    parser.IsSigned(),
                    idp.metadata != null,
                    () => parser.CheckSignature(idp.metadata.GetKeys(KeyTypes.signing)),
                    () => LogoutRequestFailure(parser.LogoutRequest, false),
                    parser.GetNameID()?.Value,
                    userId => DoSoapLogout(context, userId),
                    message => AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, message + ", issuer: " + parser.Issuer + ", msg: " + LogText.Describe(parser.SamlMessage)));
                response.StatusCode = statusCode;
                response.SubStatusCode = subStatusCode;

                LogoutRequest req = parser.LogoutRequest;

                //Build the response object
                response.Issuer = config.ServiceProvider.ID;
                response.InResponseTo = req.ID;
                XmlDocument doc = response.GetXml();
                var signingCertificate = FederationConfig.GetConfig().GetFirstValidCertificate();
                var signatureProvider = SignatureProviderFactory.CreateFromShaHashingAlgorithmName(shaHashingAlgorithm);
                signatureProvider.SignAssertion(doc, response.ID, signingCertificate);
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
                    AuditLogging.logEntry(Direction.UNDEFINED, Operation.ARTIFACTRESOLVE, string.Format("Unsupported SamlMessage element: {0}, msg: {1}", parser.SamlMessageName, LogText.Describe(parser.SamlMessage)));
                    HandleError(context, "Unsupported SamlMessage element: {0}" , parser.SamlMessageName);
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

            var assertion = Saml20PrincipalCache.GetSaml20AssertionLite();
            request.Destination = destination.Url;
            request.Reason = Saml20Constants.Reasons.User;
            request.SubjectToLogOut.Format = assertion.Subject.Format;
            request.SubjectToLogOut.Value = assertion.Subject.Value;
            request.SessionIndex = assertion.SessionIndex;

            // [OIO-SP-28] The local session ends before the request is sent, whatever the IdP answers.
            EndLocalSession(context, request.ID, endpoint.Id);

            var shaHashingAlgorithm = SignatureProviderFactory.ValidateShaHashingAlgorithm(endpoint.ShaHashingAlgorithm);
            if (destination.Binding == SAMLBinding.POST)
            {
                HttpPostBindingBuilder builder = new HttpPostBindingBuilder(destination);
                XmlDocument requestDocument = request.GetXml();
                var signingCertificate = FederationConfig.GetConfig().GetFirstValidCertificate();
                var signatureProvider = SignatureProviderFactory.CreateFromShaHashingAlgorithmName(shaHashingAlgorithm);
                signatureProvider.SignAssertion(requestDocument, request.ID, signingCertificate);
                builder.Request = requestDocument.OuterXml;

                if (Trace.ShouldTrace(TraceEventType.Verbose))
                    Trace.TraceData(TraceEventType.Verbose, string.Format(Tracing.SendLogoutRequest, "POST", endpoint.Id, requestDocument.OuterXml));

                AuditLogging.logEntry(Direction.OUT, Operation.LOGOUTREQUEST, "Binding: POST");
                builder.GetPage().ProcessRequest(context);
                context.Response.End();
                return;
            }

            if (destination.Binding == SAMLBinding.REDIRECT)
            {
                HttpRedirectBindingBuilder builder = new HttpRedirectBindingBuilder();
                builder.signingKey = FederationConfig.GetConfig().GetFirstValidCertificate().GetRSAPrivateKey();
                builder.Request = request.GetXml().OuterXml;
                builder.ShaHashingAlgorithm = shaHashingAlgorithm;

                string redirectUrl = destination.Url + "?" + builder.ToQuery();

                if (Trace.ShouldTrace(TraceEventType.Verbose))
                    Trace.TraceData(TraceEventType.Verbose, string.Format(Tracing.SendLogoutRequest, "REDIRECT", endpoint.Id, redirectUrl));

                AuditLogging.logEntry(Direction.OUT, Operation.LOGOUTREQUEST, "Binding: Redirect");
                context.Response.Redirect(redirectUrl, true);
                return;
            }

            if (destination.Binding == SAMLBinding.ARTIFACT)
            {
                if (Trace.ShouldTrace(TraceEventType.Information))
                    Trace.TraceData(TraceEventType.Information, string.Format(Tracing.SendLogoutRequest, "ARTIFACT", endpoint.Id, string.Empty));

                HttpArtifactBindingBuilder builder = new HttpArtifactBindingBuilder(context);
                AuditLogging.logEntry(Direction.OUT, Operation.LOGOUTREQUEST, "Method: Artifact");
                builder.RedirectFromLogout(endpoint, destination, request, Guid.NewGuid().ToString("N"));
            }

            HandleError(context, Resources.BindingError);
        }

        /// <summary>
        /// Ends the local session at the start of a logout this service provider initiates: runs the logout actions except
        /// the redirect, which waits for the IdP's LogoutResponse, and abandons the user's sessions. Only the ID of the
        /// LogoutRequest and the IdP it is sent to are kept, to check the LogoutResponse against.
        /// </summary>
        private void EndLocalSession(HttpContext context, string logoutRequestId, string idpId)
        {
            var userId = Saml20Identity.Current?.Name;
            try
            {
                foreach (IAction action in Actions.Actions.GetActions())
                {
                    if (action is RedirectAction)
                        continue;

                    Trace.TraceMethodCalled(action.GetType(), "LogoutAction()");
                    action.LogoutAction(this, context, false);
                    Trace.TraceMethodDone(action.GetType(), "LogoutAction()");
                }
            }
            finally
            {
                if (userId != null)
                    SessionStore.AbandonAllSessions(userId);
                SessionStore.CurrentSession[SessionConstants.Saml20AssertionLite] = null;
                SessionStore.CurrentSession[SessionConstants.PendingLogoutRequestId] = logoutRequestId;
                SessionStore.CurrentSession[SessionConstants.PendingLogoutIdpId] = idpId;
            }
        }

        /// <summary>
        /// Completes a logout this service provider initiated, when the IdP's LogoutResponse arrives. The local session
        /// already ended when the LogoutRequest was sent, so only the redirect is left, and only for a response to that request.
        /// </summary>
        /// <param name="context">The current HTTP context.</param>
        /// <param name="response">The LogoutResponse, with its signature already verified if it came through the browser.</param>
        /// <param name="destinationRequired">Whether the response must carry a Destination, as a signed message through the browser must.</param>
        private void FinishLogout(HttpContext context, LogoutResponse response, bool destinationRequired)
        {
            var session = SessionStore.CurrentSession;
            var expectedInResponseTo = session?[SessionConstants.PendingLogoutRequestId] as string;
            var expectedIdpId = session?[SessionConstants.PendingLogoutIdpId] as string;
            if (session != null)
            {
                session[SessionConstants.PendingLogoutRequestId] = null;
                session[SessionConstants.PendingLogoutIdpId] = null;
            }
            SessionStore.ExpireSessionCookie();

            var failure = CheckLogoutResponse(response, expectedInResponseTo, expectedIdpId, SingleLogoutServiceUrls(SAML20FederationConfig.GetConfig().ServiceProvider), destinationRequired);
            if (failure != null)
            {
                AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE, "LogoutResponse rejected: " + failure);
                HandleError(context, "{0}", failure);
                return;
            }

            if (response.Status?.StatusCode?.Value != Saml20Constants.StatusCodes.Success)
            {
                AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE,
                                      string.Format("Unexpected status code: {0}, response ID: {1}", response.Status?.StatusCode?.Value, response.ID));
                HandleError(context, response.Status);
                return;
            }

            AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE, "LogoutResponse validated successfully");

            foreach (IAction action in Actions.Actions.GetActions())
            {
                if (action is RedirectAction)
                    action.LogoutAction(this, context, false);
            }
        }

        /// <summary>
        /// Checks a LogoutResponse apart from its signature: it answers the LogoutRequest this service provider sent, comes
        /// from the IdP it was sent to, and is addressed to this service provider's single logout service.
        /// </summary>
        /// <returns>null if the response is acceptable, otherwise the reason it isn't.</returns>
        internal static string CheckLogoutResponse(LogoutResponse response, string expectedInResponseTo, string expectedIdpId,
            ICollection<Uri> singleLogoutServiceUrls, bool destinationRequired)
        {
            if (expectedInResponseTo == null)
                return "No logout is in progress in this session.";
            if (response.InResponseTo != expectedInResponseTo)
                return "The LogoutResponse does not answer the LogoutRequest sent by this service provider.";
            if (response.Issuer?.Value != expectedIdpId)
                return "The LogoutResponse is not issued by the IdP the LogoutRequest was sent to.";
            return CheckDestination("LogoutResponse", response.Destination, singleLogoutServiceUrls, destinationRequired);
        }

        #endregion

        #region SAMLResponse related

        private void HandleResponse(HttpContext context)
        {
            Trace.TraceMethodCalled(GetType(), "HandleResponse()");

            LogoutResponse response;

            if (context.Request.RequestType == "GET")
            {
                HttpRedirectBindingParser parser = new HttpRedirectBindingParser(context.Request.Url);
                response = Serialization.DeserializeFromXmlString<LogoutResponse>(parser.Message);

                AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE,
                                      string.Format("Binding: redirect, Signature algorithm: {0}, Message: {1}", parser.SignatureAlgorithm, LogText.Describe(parser.Message)));

                IDPEndPoint idp = RetrieveIDPConfiguration(response.Issuer?.Value);
                AuditLogging.IdpId = idp?.Id;
                AuditLogging.AssertionId = response.ID;

                if (idp?.metadata == null)
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE,
                                      string.Format("No IDP metadata, unknown IDP, response: {0}", LogText.Describe(parser.Message)));
                    SessionStore.ExpireSessionCookie();
                    HandleError(context, Resources.UnknownIDP);
                    return;
                }

                if (!parser.IsSigned || !Verifies(() => parser.VerifySignature(idp.metadata.GetKeys(KeyTypes.signing))))
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE,
                                      string.Format("Invalid signature in redirect-binding, response: {0}", LogText.Describe(parser.Message)));
                    SessionStore.ExpireSessionCookie();
                    HandleError(context, Resources.SignatureInvalid);
                    return;
                }
            }
            else if (context.Request.RequestType == "POST")
            {
                HttpPostBindingParser parser = new HttpPostBindingParser(context);
                AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE,
                                      "Binding: POST, Message: " + LogText.Describe(parser.Message));

                response = Serialization.DeserializeFromXmlString<LogoutResponse>(parser.Message);

                IDPEndPoint idp = RetrieveIDPConfiguration(response.Issuer?.Value);
                AuditLogging.IdpId = idp?.Id;
                AuditLogging.AssertionId = response.ID;

                if (idp?.metadata == null)
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE,
                                      string.Format("No IDP metadata, unknown IDP, response: {0}", LogText.Describe(parser.Message)));
                    SessionStore.ExpireSessionCookie();
                    HandleError(context, Resources.UnknownIDP);
                    return;
                }

                if (!parser.IsSigned() || !Verifies(() => parser.CheckSignature(idp.metadata.GetKeys(KeyTypes.signing))))
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE,
                                      string.Format("Missing or invalid signature in post-binding, response: {0}", LogText.Describe(parser.Message)));
                    SessionStore.ExpireSessionCookie();
                    HandleError(context, Resources.SignatureInvalid);
                    return;
                }
            }
            else
            {
                AuditLogging.logEntry(Direction.IN, Operation.LOGOUTRESPONSE,
                                      string.Format("Unsupported request type format, type: {0}", context.Request.RequestType));
                HandleError(context, Resources.UnsupportedRequestType, context.Request.RequestType);
                return;
            }

            FinishLogout(context, response, true);
        }

        #endregion

        #region SAMLRequest related

        private void HandleRequest(HttpContext context)
        {
            Trace.TraceMethodCalled(GetType(), "HandleRequest()");

            //Fetch config object
            SAML20FederationConfig config = SAML20FederationConfig.GetConfig();

            LogoutRequest logoutRequest;
            IDPEndPoint endpoint;

            //Build the response object
            var response = new Saml20LogoutResponse();
            response.Issuer = config.ServiceProvider.ID;
            response.StatusCode = Saml20Constants.StatusCodes.Success; // Default success. Is overwritten if something fails.

            if (context.Request.RequestType == "GET") // HTTP Redirect binding
            {
                HttpRedirectBindingParser parser = new HttpRedirectBindingParser(context.Request.Url);
                AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST,
                                      string.Format("Binding: redirect, Signature algorithm: {0}, Message: {1}", parser.SignatureAlgorithm, LogText.Describe(parser.Message)));

                logoutRequest = parser.LogoutRequest;
                endpoint = config.FindEndPoint(logoutRequest.Issuer?.Value);
                if (endpoint?.metadata == null)
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, "Cannot find metadata for IdP: " + logoutRequest.Issuer?.Value);
                    // Not able to return a response as we do not know the IdP.
                    HandleError(context, "Cannot find metadata for IdP {0}", logoutRequest.Issuer?.Value);
                    return;
                }

                if (!parser.IsSigned || !Verifies(() => parser.VerifySignature(endpoint.metadata.GetKeys(KeyTypes.signing))))
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, "Request has been denied. Missing or invalid signature redirect-binding, msg: " + LogText.Describe(parser.Message));
                    Deny(response);
                }
            }
            else if (context.Request.RequestType == "POST") // HTTP Post binding
            {
                HttpPostBindingParser parser = new HttpPostBindingParser(context);
                AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST,
                                      "Binding: POST, Message: " + LogText.Describe(parser.Message));

                logoutRequest = parser.LogoutRequest;
                endpoint = config.FindEndPoint(logoutRequest.Issuer?.Value);
                if (endpoint?.metadata == null)
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, "Cannot find metadata for IdP: " + logoutRequest.Issuer?.Value);
                    // Not able to return a response as we do not know the IdP.
                    HandleError(context, "Cannot find metadata for IdP {0}", logoutRequest.Issuer?.Value);
                    return;
                }

                if (!parser.IsSigned() || !Verifies(() => parser.CheckSignature(endpoint.metadata.GetKeys(KeyTypes.signing))))
                {
                    AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, "Request has been denied. Missing or invalid signature post-binding, msg: " + LogText.Describe(parser.Message));
                    Deny(response);
                }
            }
            else
            {
                //Error: We don't support HEAD, PUT, CONNECT, TRACE, DELETE and OPTIONS
                // Not able to return a response as we do not understand the request.
                HandleError(context, Resources.UnsupportedRequestType, context.Request.RequestType);
                return;
            }

            if (response.StatusCode == Saml20Constants.StatusCodes.Success)
                ProcessLogoutRequest(context, logoutRequest, endpoint, true, response);

            // Update the response object with informations that first is available when request has been parsed.
            IDPEndPointElement destination = DetermineEndpointConfiguration(SAMLBinding.REDIRECT, endpoint.SLOEndpoint, endpoint.metadata.SLOEndpoints());
            response.Destination = destination.Url;
            response.InResponseTo = logoutRequest.ID;

            //Respond using redirect binding
            var shaHashingAlgorithm = SignatureProviderFactory.ValidateShaHashingAlgorithm(endpoint.ShaHashingAlgorithm);
            if (destination.Binding == SAMLBinding.REDIRECT)
            {
                HttpRedirectBindingBuilder builder = new HttpRedirectBindingBuilder();
                builder.RelayState = context.Request.Params["RelayState"];
                builder.Response = response.GetXml().OuterXml;
                builder.signingKey = FederationConfig.GetConfig().GetFirstValidCertificate().GetRSAPrivateKey();
                builder.ShaHashingAlgorithm = shaHashingAlgorithm;
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
                var signingCertificate = FederationConfig.GetConfig().GetFirstValidCertificate();
                var signatureProvider = SignatureProviderFactory.CreateFromShaHashingAlgorithmName(shaHashingAlgorithm);
                signatureProvider.SignAssertion(responseDocument, response.ID, signingCertificate);
                builder.Response = responseDocument.OuterXml;
                builder.RelayState = context.Request.Params["RelayState"];
                builder.GetPage().ProcessRequest(context);
                return;
            }
        }

        /// <summary>
        /// Acts on an IdP's LogoutRequest whose signature, or the channel it came through, has been verified: checks it and,
        /// when it names the user of this session, logs the user out. The outcome is set on <paramref name="response"/>.
        /// </summary>
        private void ProcessLogoutRequest(HttpContext context, LogoutRequest logoutRequest, IDPEndPoint endpoint, bool destinationRequired, Saml20LogoutResponse response)
        {
            AuditLogging.AssertionId = logoutRequest.ID;

            var failure = LogoutRequestFailure(logoutRequest, destinationRequired);
            if (failure != null)
            {
                AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, "Request has been denied. " + failure);
                Deny(response);
                return;
            }

            var session = Saml20PrincipalCache.GetSaml20AssertionLite();
            if (session == null)
            {
                // All other status codes than Success results in the IdP throwing an error page. Therefore we return default Success even if we do not have a session.
                AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, "Session does not exist. Continues the logout procedure with status code success. " + endpoint.Id);
                return;
            }

            if (session.Issuer != endpoint.Id)
            {
                AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, string.Format(Resources.IdPMismatchBetweenRequestAndSession, session.Issuer, endpoint.Id));
                Deny(response);
                return;
            }

            if (!NamesSubject(logoutRequest, session))
            {
                AuditLogging.logEntry(Direction.IN, Operation.LOGOUTREQUEST, "Request has been denied. [OIO-SP-23] The NameID or SessionIndex does not match the logged-in subject");
                response.StatusCode = Saml20Constants.StatusCodes.Requester;
                response.SubStatusCode = Saml20Constants.StatusCodes.UnknownPrincipal;
                return;
            }

            DoLogout(context, true);
        }

        private static readonly (string StatusCode, string SubStatusCode) Denied =
            (Saml20Constants.StatusCodes.Requester, Saml20Constants.StatusCodes.RequestDenied);

        /// <summary>
        /// Handles a LogoutRequest received over SOAP. The user is logged out only when the request is signed by a known IdP
        /// with a valid signature, passes the checks of <see cref="LogoutRequestFailure"/> and names a user.
        /// </summary>
        /// <param name="isSigned">Whether the request carries a signature.</param>
        /// <param name="isIdpKnown">Whether metadata exists for the issuing IdP.</param>
        /// <param name="isSignatureValid">Verifies the signature against the IdP's signing keys; only called for a signed request from a known IdP.</param>
        /// <param name="failure">Checks the request apart from its signature, returning the reason it is refused or null; only called once the signature is valid.</param>
        /// <param name="userId">The NameID of the user to log out.</param>
        /// <param name="logOut">Logs the user out.</param>
        /// <param name="audit">Writes an audit log entry for a denied request.</param>
        /// <returns>The status codes for the LogoutResponse: Success, or Requester with the reason as second-level status code.</returns>
        internal static (string StatusCode, string SubStatusCode) HandleSoapLogoutRequest(bool isSigned, bool isIdpKnown, Func<bool> isSignatureValid,
            Func<string> failure, string userId, Action<string> logOut, Action<string> audit)
        {
            if (!isSigned)
            {
                audit("Request has been denied. Signature not present in SOAP logout request");
                return Denied;
            }

            if (!isIdpKnown)
            {
                audit("Request has been denied. Cannot find metadata for IdP");
                return Denied;
            }

            if (!isSignatureValid())
            {
                audit("Request has been denied. Invalid signature SOAP logout");
                return Denied;
            }

            var reason = failure();
            if (reason != null)
            {
                audit("Request has been denied. " + reason);
                return Denied;
            }

            if (string.IsNullOrEmpty(userId))
            {
                audit("Request has been denied. No user ID was supplied in SOAP logout request");
                return (Saml20Constants.StatusCodes.Requester, Saml20Constants.StatusCodes.UnknownPrincipal);
            }

            logOut(userId);
            return (Saml20Constants.StatusCodes.Success, null);
        }

        /// <summary>
        /// Denies a LogoutRequest: top-level status Requester, with RequestDenied as the reason.
        /// </summary>
        private static void Deny(Saml20LogoutResponse response)
        {
            response.StatusCode = Denied.StatusCode;
            response.SubStatusCode = Denied.SubStatusCode;
        }

        /// <summary>
        /// How old a LogoutRequest may be. The IdP sends it as soon as it issues it; an older one may be a replay.
        /// </summary>
        internal static readonly TimeSpan LogoutRequestMaximumAge = TimeSpan.FromMinutes(5);

        private const string LogoutRequestCacheKeyPrefix = "dk.nita.saml20.logoutrequest:";

        /// <summary>
        /// Checks an IdP's LogoutRequest apart from its signature and the session, and accepts each request ID once.
        /// </summary>
        /// <returns>null if the request is acceptable, otherwise the reason it isn't.</returns>
        private static string LogoutRequestFailure(LogoutRequest logoutRequest, bool destinationRequired)
        {
            var skew = TimeSpan.FromMinutes(FederationConfig.GetConfig().AllowedClockSkewMinutes);
            var now = DateTime.UtcNow;
            var failure = CheckLogoutRequest(logoutRequest, SingleLogoutServiceUrls(SAML20FederationConfig.GetConfig().ServiceProvider), destinationRequired, now, skew);
            if (failure != null)
                return failure;

            var acceptedUntil = logoutRequest.IssueInstant.Value + LogoutRequestMaximumAge + skew;
            var isNew = HttpRuntime.Cache.Add(LogoutRequestCacheKeyPrefix + logoutRequest.ID, string.Empty, null, acceptedUntil,
                Cache.NoSlidingExpiration, CacheItemPriority.NotRemovable, null) == null;
            return isNew ? null : "The LogoutRequest has been received before.";
        }

        /// <summary>
        /// Checks an IdP's LogoutRequest apart from its signature and the session: it has an ID, is addressed to this
        /// service provider's single logout service, was issued within <see cref="LogoutRequestMaximumAge"/> and has not expired.
        /// </summary>
        /// <returns>null if the request is acceptable, otherwise the reason it isn't.</returns>
        internal static string CheckLogoutRequest(LogoutRequest logoutRequest, ICollection<Uri> singleLogoutServiceUrls, bool destinationRequired, DateTime now, TimeSpan skew)
        {
            if (string.IsNullOrEmpty(logoutRequest.ID))
                return "The LogoutRequest has no ID.";

            var destinationFailure = CheckDestination("LogoutRequest", logoutRequest.Destination, singleLogoutServiceUrls, destinationRequired);
            if (destinationFailure != null)
                return destinationFailure;

            if (!logoutRequest.IssueInstant.HasValue)
                return "The LogoutRequest has no IssueInstant.";
            if (logoutRequest.IssueInstant.Value - skew > now || logoutRequest.IssueInstant.Value + LogoutRequestMaximumAge + skew <= now)
                return $"[OIO-GE-01] The LogoutRequest IssueInstant is in the future or more than {LogoutRequestMaximumAge.TotalMinutes} minutes old.";

            if (logoutRequest.NotOnOrAfter.HasValue && logoutRequest.NotOnOrAfter.Value + skew <= now)
                return "[OIO-GE-01] The LogoutRequest has expired.";

            return null;
        }

        /// <summary>
        /// [OIO-SP-23] Whether the LogoutRequest names the subject of the session: the same NameID value and format and,
        /// if the request lists session indexes, the session's among them.
        /// </summary>
        internal static bool NamesSubject(LogoutRequest logoutRequest, Saml20AssertionLite session)
        {
            if (!(logoutRequest.Item is Schema.Core.NameID nameId) || session.Subject == null)
                return false;
            if (nameId.Value != session.Subject.Value || nameId.Format != session.Subject.Format)
                return false;
            return logoutRequest.SessionIndex == null || logoutRequest.SessionIndex.Length == 0
                || Array.IndexOf(logoutRequest.SessionIndex, session.SessionIndex) >= 0;
        }

        private static string CheckDestination(string messageName, string destination, ICollection<Uri> singleLogoutServiceUrls, bool required)
        {
            if (destination == null)
                return required ? $"The {messageName} has no Destination." : null;
            if (!Uri.TryCreate(destination, UriKind.Absolute, out var url) || !singleLogoutServiceUrls.Contains(url))
                return $"The {messageName} Destination is not this service provider's single logout service.";
            return null;
        }

        /// <summary>
        /// The single logout service URLs, as published in the service provider's metadata.
        /// </summary>
        internal static ICollection<Uri> SingleLogoutServiceUrls(ServiceProviderElement serviceProvider)
        {
            return serviceProvider.serviceEndpoints
                .Where(e => e.endpointType == EndpointType.LOGOUT)
                .Select(serviceProvider.GetEndpointUrl)
                .ToList();
        }

        /// <summary>
        /// Runs a signature check; a signature that can't be processed counts as invalid.
        /// </summary>
        private static bool Verifies(Func<bool> checkSignature)
        {
            try
            {
                return checkSignature();
            }
            catch (Exception e) when (!(e is ThreadAbortException))
            {
                Trace.TraceData(TraceEventType.Warning, "The signature could not be verified: " + e.Message);
                return false;
            }
        }

        #endregion

        #region Private utility functions

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
                var userId = SessionStore.CurrentSession != null ? Saml20Identity.Current?.Name : null;
                if (userId != null)
                {
                    // Always end with abandoning the session.
                    Trace.TraceData(TraceEventType.Information, "Clearing session for userId: " + userId);
                    SessionStore.AbandonAllSessions(userId);
                    Trace.TraceData(TraceEventType.Verbose, "Session cleared.");
                }
                else
                {
                    Trace.TraceData(TraceEventType.Warning, "The user was logged out but the session had already expired. Distributed session could therefore not be abandoned");
                }

                SessionStore.ExpireSessionCookie();
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
                SessionStore.AbandonAllSessions(userId);
                Trace.TraceData(TraceEventType.Verbose, "Sessions cleared.");
            }
        }

        #endregion
    }
}
