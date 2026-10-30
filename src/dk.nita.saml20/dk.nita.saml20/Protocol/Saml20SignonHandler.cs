using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Web.Caching;
using System.Xml;
using dk.nita.saml20.Actions;
using dk.nita.saml20.AuthnRequestAppender;
using dk.nita.saml20.Bindings;
using dk.nita.saml20.Bindings.SignatureProviders;
using dk.nita.saml20.Profiles.DKSaml20.Attributes;
using dk.nita.saml20.Session;
using dk.nita.saml20.session;
using dk.nita.saml20.config;
using dk.nita.saml20.Logging;
using dk.nita.saml20.Properties;
using dk.nita.saml20.protocol.pages;
using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.Schema.Metadata;
using dk.nita.saml20.Schema.Protocol;
using dk.nita.saml20.Specification;
using dk.nita.saml20.Utils;
using Saml2.Properties;
using Extensions = dk.nita.saml20.Schema.Protocol.Extensions;
using Trace = dk.nita.saml20.Utils.Trace;

namespace dk.nita.saml20.protocol
{
    /// <summary>
    /// Implements a Saml 2.0 protocol sign-on endpoint. Handles all SAML bindings.
    /// </summary>
    public class Saml20SignonHandler : Saml20AbstractEndpointHandler
    {
        private const string ReplayCacheKeyPrefix = "dk.nita.saml20.assertion:";

        /// <summary>
        /// The AuthnRequest a response must answer: its ID and the IdP it was sent to.
        /// </summary>
        private readonly struct PendingAuthnRequest
        {
            internal PendingAuthnRequest(string requestId, string idpId)
            {
                RequestId = requestId;
                IdpId = idpId;
            }

            internal string RequestId { get; }

            internal string IdpId { get; }
        }

        private readonly X509Certificate2 _certificate;

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20SignonHandler"/> class.
        /// </summary>
        public Saml20SignonHandler()
        {
            _certificate = FederationConfig.GetConfig().GetFirstValidCertificate();

            // Read the proper redirect url from config
            try
            {
                RedirectUrl = SAML20FederationConfig.GetConfig().ServiceProvider.SignOnEndpoint.RedirectUrl;
                ErrorBehaviour = SAML20FederationConfig.GetConfig().ServiceProvider.SignOnEndpoint.ErrorBehaviour.ToString();
            }
            catch (Exception e)
            {
                if (Trace.ShouldTrace(TraceEventType.Error))
                    Trace.TraceData(TraceEventType.Error, e.ToString());
            }
        }

        #region IHttpHandler Members

        /// <summary>
        /// Handles a request.
        /// </summary>
        /// <param name="context">The context.</param>
        protected override void Handle(HttpContext context)
        {
            Trace.TraceMethodCalled(GetType(), "Handle()");

            //Some IdP's are known to fail to set an actual value in the SOAPAction header
            //so we just check for the existence of the header field.
            if (Array.Exists(context.Request.Headers.AllKeys, delegate (string s) { return s == SOAPConstants.SOAPAction; }))
            {
                SessionStore.AssertSessionExists();

                HandleSOAP(context, context.Request.InputStream, null);
                return;
            }

            if (!string.IsNullOrEmpty(context.Request.Params["SAMLart"]))
            {
                SessionStore.AssertSessionExists();

                HandleArtifact(context);
            }

            if (!string.IsNullOrEmpty(context.Request.Params["SamlResponse"]))
            {
                SessionStore.AssertSessionExists();

                HandleResponse(context);
            }
            else
            {
                if (SAML20FederationConfig.GetConfig().CommonDomain.Enabled && context.Request.QueryString["r"] == null
                    && context.Request.Params["cidp"] == null)
                {
                    AuditLogging.logEntry(Direction.OUT, Operation.DISCOVER, "Redirecting to Common Domain for IDP discovery");
                    context.Response.Redirect(SAML20FederationConfig.GetConfig().CommonDomain.LocalReaderEndpoint);
                }
                else
                {
                    AuditLogging.logEntry(Direction.IN, Operation.ACCESS,
                                                 "User accessing resource: " + context.Request.RawUrl +
                                                 " without authentication.");

                    SessionStore.CreateSessionIfNotExists();

                    SendRequest(context);
                }
            }
        }

        #endregion

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

            if (parser.IsArtifactResolve())
            {
                Trace.TraceData(TraceEventType.Information, Tracing.ArtifactResolveIn);

                IDPEndPoint idp = RetrieveIDPConfiguration(parser.Issuer);
                AuditLogging.IdpId = idp.Id;
                AuditLogging.AssertionId = parser.ArtifactResolve.ID;
                if (!parser.CheckSamlMessageSignature(idp.metadata.Keys))
                {
                    HandleError(context, "Invalid SAML message signature");
                    AuditLogging.logEntry(Direction.IN, Operation.ARTIFACTRESOLVE, "Could not verify signature", parser.SamlMessage);
                }
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
                    HandleError(context, status);
                    AuditLogging.logEntry(Direction.IN, Operation.ARTIFACTRESOLVE, string.Format("Illegal status for ArtifactResponse {0} expected 'Success', msg: {1}", status.StatusCode.Value, LogText.Describe(parser.SamlMessage)));
                    return;
                }
                if (parser.ArtifactResponse.Any.LocalName == Response.ELEMENT_NAME)
                {
                    XmlElement response = parser.ArtifactResponse.Any;
                    var pendingRequest = CheckReplayAttack(context, response.GetAttribute("InResponseTo"));

                    Status responseStatus = GetStatusElement(response);
                    if (responseStatus.StatusCode.Value != Saml20Constants.StatusCodes.Success)
                    {
                        HandleError(context, responseStatus);
                        return;
                    }

                    HandleEncryptedAssertion(context, GetEncryptedAssertion(response), pendingRequest);
                }
                else
                {
                    AuditLogging.logEntry(Direction.IN, Operation.ARTIFACTRESOLVE, string.Format("Unsupported payload message in ArtifactResponse: {0}, msg: {1}", parser.ArtifactResponse.Any.LocalName, LogText.Describe(parser.SamlMessage)));
                    HandleError(context,"Unsupported payload message in ArtifactResponse: {0}",parser.ArtifactResponse.Any.LocalName);
                }
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
                    AuditLogging.logEntry(Direction.IN, Operation.ARTIFACTRESOLVE, string.Format("Unsupported SamlMessage element: {0}, msg: {1}", parser.SamlMessageName, LogText.Describe(parser.SamlMessage)));
                    HandleError(context, "Unsupported SamlMessage element: {0}", parser.SamlMessageName);
                }
            }
        }

        /// <summary>
        /// Send an authentication request to the IDP.
        /// </summary>
        private void SendRequest(HttpContext context)
        {
            Trace.TraceMethodCalled(GetType(), "SendRequest()");

            // See if the "ReturnUrl" - parameter is set.
            string returnUrl = context.Request.QueryString["ReturnUrl"];
            // If PreventOpenRedirectAttack has been enabled ... the return URL is only set if the URL is local.
            if (!string.IsNullOrEmpty(returnUrl) && (!FederationConfig.GetConfig().PreventOpenRedirectAttack || IsLocalUrl(returnUrl)))
                SessionStore.CurrentSession[SessionConstants.RedirectUrl] = returnUrl;

            IDPEndPoint idpEndpoint = RetrieveIDP(context);

            if (idpEndpoint == null)
            {
                //Display a page to the user where she can pick the IDP
                SelectSaml20IDP page = new SelectSaml20IDP();
                
                page.ProcessRequest(context);
                return;
            }

            Saml20AuthnRequest authnRequest = Saml20AuthnRequest.GetDefault();
            TransferClient(idpEndpoint, authnRequest, context);
        }

        /// <summary>
        /// This method is used for preventing open redirect attacks.
        /// </summary>
        /// <param name="url">URL that is checked for being local or not.</param>
        /// <returns>Returns true if URL is local. Empty or null strings are not considered as local URL's</returns>
        private bool IsLocalUrl(string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return false;
            }
            else
            {
                return ((url[0] == '/' && (url.Length == 1 ||
                        (url[1] != '/' && url[1] != '\\'))) ||   // "/" or "/foo" but not "//" or "/\"
                        (url.Length > 1 &&
                         url[0] == '~' && url[1] == '/'));   // "~/" or "~/foo"
            }
        }

        private Status GetStatusElement(XmlElement response)
        {
            XmlElement statElem =
                (XmlElement)response.GetElementsByTagName(Status.ELEMENT_NAME, Saml20Constants.PROTOCOL)[0];

            return Serialization.DeserializeFromXmlString<Status>(statElem.OuterXml);
        }

        /// <summary>
        /// Returns the single EncryptedAssertion of a response. The profile requires encrypted assertions, so a plain Assertion is rejected.
        /// </summary>
        internal static XmlElement GetEncryptedAssertion(XmlElement response)
        {
            XmlElement assertion = GetAssertion(response, out var isEncrypted);
            if (assertion == null)
                throw new Saml20Exception(Resources.EncryptedAssertionMissing);
            if (!isEncrypted)
                throw new Saml20Exception(Resources.AssertionNotEncrypted);
            return assertion;
        }

        internal static XmlElement GetAssertion(XmlElement el, out bool isEncrypted)
        {

            XmlNodeList encryptedList =
                el.GetElementsByTagName(EncryptedAssertion.ELEMENT_NAME, Saml20Constants.ASSERTION);

            if (encryptedList.Count == 1)
            {
                isEncrypted = true;
                return (XmlElement)encryptedList[0];
            }

            XmlNodeList assertionList =
                el.GetElementsByTagName(Assertion.ELEMENT_NAME, Saml20Constants.ASSERTION);

            if (assertionList.Count == 1)
            {
                isEncrypted = false;
                return (XmlElement)assertionList[0];
            }

            isEncrypted = false;
            return null;
        }

        /// <summary>
        /// Handle the authentication response from the IDP.
        /// </summary>        
        private void HandleResponse(HttpContext context)
        {
            Encoding defaultEncoding = Encoding.UTF8;
            XmlDocument doc = GetDecodedSamlResponse(context, defaultEncoding);

            AuditLogging.logEntry(Direction.IN, Operation.LOGIN, "Received SAMLResponse: " + LogText.Describe(doc.DocumentElement));

            try
            {

                var inResponseToAttribute = doc.DocumentElement.Attributes["InResponseTo"];

                if (inResponseToAttribute == null)
                    throw new Saml20Exception("Received a response message that did not contain an InResponseTo attribute");

                string inResponseTo = inResponseToAttribute.Value;

                var pendingRequest = CheckReplayAttack(context, inResponseTo);

                Status status = GetStatusElement(doc.DocumentElement);

                if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
                {
                    if (status.StatusCode.Value == Saml20Constants.StatusCodes.Responder && status.StatusCode.SubStatusCode != null && Saml20Constants.StatusCodes.NoPassive == status.StatusCode.SubStatusCode.Value)
                        HandleError(context, Resources.SamlNoPassiveError);

                    HandleError(context, status);
                    return;
                }

                XmlElement assertion = GetDecryptedAssertion(GetEncryptedAssertion(doc.DocumentElement)).Assertion.DocumentElement;

                // Check if an encoding-override exists for the IdP endpoint in question
                string issuer = GetIssuer(assertion);
                IDPEndPoint endpoint = RetrieveIDPConfiguration(issuer);
                if (endpoint != null && !string.IsNullOrEmpty(endpoint.ResponseEncoding))
                {
                    Encoding encodingOverride = null;
                    try
                    {
                        encodingOverride = System.Text.Encoding.GetEncoding(endpoint.ResponseEncoding);
                    }
                    catch (ArgumentException ex)
                    {
                        HandleError(context, ex);
                        return;
                    }

                    if (encodingOverride.CodePage != defaultEncoding.CodePage)
                    {
                        XmlDocument doc1 = GetDecodedSamlResponse(context, encodingOverride);
                        assertion = GetDecryptedAssertion(GetEncryptedAssertion(doc1.DocumentElement)).Assertion.DocumentElement;
                    }
                }

                HandleAssertion(context, assertion, pendingRequest);
                return;
            }
            catch (Exception ex)
            {
                if (ex is Saml20NsisLoaException)
                {
                    HandleError(context, ex.ToString(), (m) => new Saml20NsisLoaException(m));
                }
                else
                {
                    HandleError(context, ex);
                }
                return;
            }
        }

        /// <summary>
        /// Consumes the pending AuthnRequest of the session and checks that the response answers it.
        /// </summary>
        /// <returns>The ID of the AuthnRequest and the ID of the IdP it was sent to.</returns>
        private static PendingAuthnRequest CheckReplayAttack(HttpContext context, string inResponseTo)
        {
            if (string.IsNullOrEmpty(inResponseTo))
                throw new Saml20Exception("Empty InResponseTo from IdP is not allowed.");

            var expectedInResponseToSessionState = SessionStore.CurrentSession[SessionConstants.ExpectedInResponseTo];
            var expectedIdpId = SessionStore.CurrentSession[SessionConstants.ExpectedIdpId]?.ToString();
            SessionStore.CurrentSession[SessionConstants.ExpectedInResponseTo] = null; // Ensure that no more responses can be received.
            SessionStore.CurrentSession[SessionConstants.ExpectedIdpId] = null;

            string expectedInResponseTo = expectedInResponseToSessionState?.ToString();
            if (string.IsNullOrEmpty(expectedInResponseTo))
                throw new Saml20Exception("Expected InResponseTo not found in current session.");

            if (inResponseTo != expectedInResponseTo)
            {
                AuditLogging.logEntry(Direction.IN, Operation.LOGIN, string.Format("Unexpected value {0} for InResponseTo, expected {1}, possible replay attack!", inResponseTo, expectedInResponseTo));
                throw new Saml20Exception("Replay attack.");
            }

            return new PendingAuthnRequest(expectedInResponseTo, expectedIdpId);
        }

        private static XmlDocument GetDecodedSamlResponse(HttpContext context, Encoding encoding)
        {
            string base64 = context.Request.Params["SAMLResponse"];

            string samlResponse = encoding.GetString(Convert.FromBase64String(base64));
            if (Trace.ShouldTrace(TraceEventType.Verbose))
                Trace.TraceData(TraceEventType.Verbose, "Decoded SAMLResponse", samlResponse);

            return SafeXml.Load(samlResponse);
        }

        /// <summary>
        /// Decrypts an encrypted assertion, and sends the result to the HandleAssertion method.
        /// </summary>
        private void HandleEncryptedAssertion(HttpContext context, XmlElement elem, PendingAuthnRequest pendingRequest)
        {
            Trace.TraceMethodCalled(GetType(), "HandleEncryptedAssertion()");
            Saml20EncryptedAssertion decryptedAssertion = GetDecryptedAssertion(elem);
            HandleAssertion(context, decryptedAssertion.Assertion.DocumentElement, pendingRequest);
        }

        /// <summary>
        /// Decrypts an encrypted assertion if any of the configured certificates contains the correct
        /// private key to use for decrypting. If no configured certificates can be used to decrypt the
        /// encrypted assertion, the first exception will be rethrown.
        /// </summary>
        /// <param name="elem"></param>
        /// <returns></returns>
        private static Saml20EncryptedAssertion GetDecryptedAssertion(XmlElement elem)
        {
            var tryDecryptAssertion = new Func<X509Certificate2, Saml20EncryptedAssertion>((certificate) =>
            {
                Saml20EncryptedAssertion decryptedAssertion = new Saml20EncryptedAssertion(certificate.GetRSAPrivateKey());
                decryptedAssertion.LoadXml(elem);
                decryptedAssertion.Decrypt();
                return decryptedAssertion;
            });

            var allValidX509Certificates = new List<X509Certificate2>();
            foreach (var certificate in FederationConfig.GetConfig().SigningCertificates)
            {
                var x509Certificates = certificate.GetAllValidX509Certificates();
                if (x509Certificates == null)
                    continue;

                foreach (var x in x509Certificates)
                {
                    allValidX509Certificates.Add(x);
                }
            }

            foreach (var certificate in allValidX509Certificates)
            {
                try
                {
                    return tryDecryptAssertion(certificate);
                }
                catch (Exception firstFailure)
                {
                    foreach (var certificate2 in allValidX509Certificates)
                    {
                        if (certificate != certificate2)
                        {
                            try
                            {
                                return tryDecryptAssertion(certificate2);
                            }
                            catch (Exception)
                            {
                                continue;
                            }
                        }
                    }

                    // One message for every failure, so that the response doesn't tell why decryption failed.
                    Trace.TraceData(TraceEventType.Error, "The assertion could not be decrypted: " + firstFailure);
                    throw new Saml20Exception("The assertion could not be decrypted.");
                }
            }

            var msg = $"Found no valid certificate configured in the certificate configuration. Make sure at least one valid certificate is configured.";
            throw new ConfigurationErrorsException(msg);
        }

        /// <summary>
        /// Retrieves the name of the issuer from an XmlElement containing an assertion.
        /// </summary>
        /// <param name="assertion">An XmlElement containing an assertion</param>
        /// <returns>The identifier of the Issuer</returns>
        private string GetIssuer(XmlElement assertion)
        {
            string result = string.Empty;
            XmlNodeList list = assertion.GetElementsByTagName("Issuer", Saml20Constants.ASSERTION);
            if (list.Count > 0)
            {
                XmlElement issuer = (XmlElement)list[0];
                result = issuer.InnerText;
            }

            return result;
        }

        /// <summary>
        /// Is called before the assertion is made into a strongly typed representation
        /// </summary>
        /// <param name="context">The httpcontext.</param>
        /// <param name="elem">The assertion element.</param>
        /// <param name="endpoint">The endpoint.</param>
        protected virtual void PreHandleAssertion(HttpContext context, XmlElement elem, IDPEndPoint endpoint)
        {
            Trace.TraceMethodCalled(GetType(), "PreHandleAssertion");

            if (endpoint != null && endpoint.SLOEndpoint != null && !String.IsNullOrEmpty(endpoint.SLOEndpoint.IdpTokenAccessor))
            {
                ISaml20IdpTokenAccessor idpTokenAccessor =
                    Activator.CreateInstance(Type.GetType(endpoint.SLOEndpoint.IdpTokenAccessor, false)) as ISaml20IdpTokenAccessor;
                if (idpTokenAccessor != null)
                    idpTokenAccessor.ReadToken(elem);
            }

            Trace.TraceMethodDone(GetType(), "PreHandleAssertion");
        }

        /// <summary>
        /// Deserializes an assertion, verifies its signature and logs in the user if the assertion is valid.
        /// </summary>
        private void HandleAssertion(HttpContext context, XmlElement elem, PendingAuthnRequest pendingRequest)
        {
            Trace.TraceMethodCalled(GetType(), "HandleAssertion");

            string issuer = GetIssuer(elem);

            IDPEndPoint endp = RetrieveIDPConfiguration(issuer);

            if (endp == null || endp.metadata == null)
            {
                AuditLogging.logEntry(Direction.IN, Operation.AUTHNREQUEST_POST,
                          "Unknown login IDP, issuer: " + issuer);

                HandleError(context, Resources.UnknownLoginIDP);
                return;
            }

            AuditLogging.IdpId = endp.Id;

            // The assertion must come from the IdP the AuthnRequest was sent to.
            if (endp.Id != pendingRequest.IdpId)
            {
                AuditLogging.logEntry(Direction.IN, Operation.AUTHNREQUEST_POST,
                          string.Format(Resources.AssertionFromOtherIdP, endp.Id, pendingRequest.IdpId));

                HandleError(context, Resources.AssertionFromOtherIdP, endp.Id, pendingRequest.IdpId);
                return;
            }

            PreHandleAssertion(context, elem, endp);

            bool quirksMode = endp.QuirksMode;

            Saml20Assertion assertion = new Saml20Assertion(elem, null, quirksMode);
            assertion.Validate(DateTime.UtcNow);

            if (!endp.OmitAssertionSignatureCheck)
            {
                IEnumerable<string> validationFailures;
                if (!assertion.CheckSignature(GetTrustedSigners(endp.metadata.GetKeys(KeyTypes.signing), endp, out validationFailures)))
                {
                    AuditLogging.logEntry(Direction.IN, Operation.AUTHNREQUEST_POST,
                    "Invalid signature, assertion: " + LogText.Describe(elem));

                    string errorMessage = Resources.SignatureInvalid;

                    validationFailures = validationFailures.ToArray();
                    if (validationFailures.Any())
                    {
                        errorMessage += $"\nVerification of IDP certificate used for signature failed from the following certificate checks:\n{string.Join("\n", validationFailures)}";
                    }

                    HandleError(context, errorMessage);
                    return;
                }
            }

            // The signed bearer confirmation binds the assertion to the AuthnRequest and to this service provider's ACS.
            var confirmationFailure = CheckBearerConfirmation(assertion.Assertion, pendingRequest.RequestId,
                AssertionConsumerServiceUrls(SAML20FederationConfig.GetConfig().ServiceProvider), out var confirmation);
            if (confirmationFailure != null)
            {
                AuditLogging.logEntry(Direction.IN, Operation.AUTHNREQUEST_POST, "Assertion rejected: " + confirmationFailure);
                HandleError(context, "{0}", confirmationFailure);
                return;
            }

            // The assertion is valid until the NotOnOrAfter of the bearer confirmation that matched, plus the allowed clock skew.
            var validUntil = confirmation.NotOnOrAfter.Value.AddMinutes(FederationConfig.GetConfig().AllowedClockSkewMinutes);
            if (DateTime.UtcNow >= validUntil)
            {
                AuditLogging.logEntry(Direction.IN, Operation.AUTHNREQUEST_POST,
                "Assertion expired, assertion: " + LogText.Describe(elem));

                HandleError(context, Resources.AssertionExpired);
                return;
            }

            if (!ValidateLoA(context, assertion, elem)) return;

            if (!TryRegisterAssertion(assertion.Id, validUntil))
            {
                AuditLogging.logEntry(Direction.IN, Operation.AUTHNREQUEST_POST, "Assertion rejected: " + Resources.AssertionReplayed);
                HandleError(context, Resources.AssertionReplayed);
                return;
            }

            AuditLogging.AssertionId = assertion.Id;
            AuditLogging.logEntry(Direction.IN, Operation.AUTHNREQUEST_POST,
                      "Assertion validated succesfully");

            DoLogin(context, assertion);
        }

        /// <summary>
        /// Validates the LoA of the session to determine if it adheres to the configured requirements of the service provider.
        /// If validation fails, response is modified to display an error page.
        /// </summary>
        /// <returns>True if valid, otherwise false.</returns>
        private bool ValidateLoA(HttpContext context, Saml20Assertion assertion, XmlElement assertionXml)
        {
            // If AssuranceLevel is allowed, and it's present in assertion, validate. A demanded NSIS LoA always needs a NSIS LoA.
            var allowAL = SAML20FederationConfig.GetConfig().AllowAssuranceLevel;
            var assertionAL = GetAssuranceLevel(assertion);
            var demandedNsisLoa = SessionStore.CurrentSession[SessionConstants.ExpectedNsisLoa]?.ToString();
            if (UsesLegacyAssuranceLevel(allowAL, assertionAL, demandedNsisLoa))
            {
                return ValidateAssuranceLevel(assertionAL, context, assertionXml);
            }

            // If NSIS LoA is missing, invalidate.
            var assertionNsisLoa = GetNsisLoa(assertion);
            if (assertionNsisLoa == null)
            {
                AuditLogging.logEntry(Direction.IN, Operation.AUTHNREQUEST_POST, Resources.NsisLoaMissing + " Assertion: " + LogText.Describe(assertionXml));
                HandleError(context, Resources.NsisLoaMissing);
                return false;
            }

            return ValidateNsisLoa(assertionNsisLoa, demandedNsisLoa, context, assertionXml);
        }

        /// <summary>
        /// Whether the legacy OIOSAML 2 AssuranceLevel is validated instead of the NSIS LoA: only when it is allowed,
        /// present in the assertion, and no NSIS LoA was demanded.
        /// </summary>
        internal static bool UsesLegacyAssuranceLevel(bool allowAssuranceLevel, string assuranceLevel, string demandedNsisLoa)
        {
            return allowAssuranceLevel && assuranceLevel != null && demandedNsisLoa == null;
        }

        /// <summary>
        /// Checks a NSIS LoA demanded in the login request: it must be a NSIS level and at least the configured minimum.
        /// </summary>
        /// <returns>null if the demand can be sent to the IdP, otherwise the error message template ({0} the demand, {1} the minimum).</returns>
        internal static string DemandedNsisLoaError(string demandedNsisLoa, string configuredNsisLoa)
        {
            if (!DKSaml20NsisLoaAttribute.IsValidLevel(demandedNsisLoa))
                return Resources.DemandingLevelOfAssuranceError;

            if (!DKSaml20NsisLoaAttribute.IsAtLeast(demandedNsisLoa, configuredNsisLoa))
                return Resources.DemandingLevelOfAssuranceBelowMinimum;

            return null;
        }

        /// <summary>
        /// Validates if a NSIS LoA is equals to or higher than a minimum required LoA: the configured minimum, or a stricter demanded LoA.
        /// If validation fails, response is modified to display an error page.
        /// </summary>
        /// <returns>True if valid, otherwise false (and modified response).</returns>
        private bool ValidateNsisLoa(string loa, string demandedNsisLoa, HttpContext context, XmlElement assertionXml)
        {
            var configuredNsisLoa = SAML20FederationConfig.GetConfig().MinimumNsisLoa;
            var minLoa = DKSaml20NsisLoaAttribute.Stricter(configuredNsisLoa, demandedNsisLoa);

            if (DKSaml20NsisLoaAttribute.IsAtLeast(loa, minLoa)) return true;

            var msgTemplate = minLoa != configuredNsisLoa ?
                Resources.NsisLoaTooLowAccordingToDemand :
                Resources.NsisLoaTooLow;
            HandleLoaValidationError(msgTemplate, loa, minLoa, context, assertionXml);
            return false;
        }

        /// <summary>
        /// Validates if a AssuranceLevel is equals to or higher than a minimum required AssuranceLevel.
        /// If validation fails, response is modified to display an error page.
        /// </summary>
        /// <returns>True if valid, otherwise false (and modified response).</returns>
        private bool ValidateAssuranceLevel(string assouranceLevel, HttpContext context, XmlElement assertionXml)
        {
            var minAL = SAML20FederationConfig.GetConfig().MinimumAssuranceLevel;
            
            if (assouranceLevel != null &&
                int.TryParse(assouranceLevel, out var sourceLoaInt) &&
                int.TryParse(minAL, out var minLoaInt) &&
                sourceLoaInt >= minLoaInt)
            {
                return true;
            }

            HandleLoaValidationError(Resources.NsisLoaTooLow, assouranceLevel, minAL, context, assertionXml);
            return false;
        }

        internal static IEnumerable<AsymmetricAlgorithm> GetTrustedSigners(ICollection<KeyDescriptor> keys, IDPEndPoint ep, out IEnumerable<string> validationFailureReasons)
        {
            if (keys == null)
                throw new ArgumentNullException("keys");

            var failures = new List<string>();
            List<AsymmetricAlgorithm> result = new List<AsymmetricAlgorithm>(keys.Count);
            foreach (KeyDescriptor keyDescriptor in keys)
            {
                KeyInfo ki = (KeyInfo)keyDescriptor.KeyInfo;

                foreach (KeyInfoClause clause in ki)
                {
                    if (clause is KeyInfoX509Data)
                    {
                        X509Certificate2 cert = XmlSignatureUtils.GetCertificateFromKeyInfo((KeyInfoX509Data)clause);

                        string failureReason;
                        if (!IsSatisfiedByAllSpecifications(ep, cert, out failureReason))
                        {
                            failures.Add(failureReason);
                            continue;
                        }
                    }

                    AsymmetricAlgorithm key = XmlSignatureUtils.ExtractKey(clause);
                    if (key != null)
                        result.Add(key);
                }

            }

            validationFailureReasons = failures;
            return result;
        }

        private static bool IsSatisfiedByAllSpecifications(IDPEndPoint ep, X509Certificate2 cert, out string failureReason)
        {
            foreach (ICertificateSpecification spec in SpecificationFactory.GetCertificateSpecifications(ep))
            {
                string r;
                if (!spec.IsSatisfiedBy(cert, out r))
                {
                    failureReason = $"{spec.GetType().Name}: {r}";
                    return false;

                }
            }

            failureReason = null;
            return true;
        }

        /// <summary>
        /// Checks that the assertion has a bearer SubjectConfirmation whose signed SubjectConfirmationData answers the
        /// AuthnRequest (InResponseTo) and is addressed to one of this service provider's assertion consumer services (Recipient).
        /// </summary>
        /// <param name="assertion">The assertion, after its signature has been verified.</param>
        /// <param name="expectedRequestId">The ID of the AuthnRequest of the session.</param>
        /// <param name="assertionConsumerServiceUrls">The service provider's assertion consumer service URLs.</param>
        /// <param name="confirmation">The bearer SubjectConfirmationData that matched, which has a NotOnOrAfter; null if none did.</param>
        /// <returns>null if such a confirmation exists, otherwise the reason for rejecting the assertion [OIO-IDP-17].</returns>
        internal static string CheckBearerConfirmation(Assertion assertion, string expectedRequestId, ICollection<Uri> assertionConsumerServiceUrls, out SubjectConfirmationData confirmation)
        {
            confirmation = null;
            var answering = (assertion.Subject?.Items ?? new object[0])
                .OfType<SubjectConfirmation>()
                .Where(c => c.Method == SubjectConfirmation.BEARER_METHOD && c.SubjectConfirmationData != null)
                .Select(c => c.SubjectConfirmationData)
                .Where(d => !string.IsNullOrEmpty(expectedRequestId) && d.InResponseTo == expectedRequestId)
                .ToList();

            if (!answering.Any())
                return string.Format(Resources.AssertionNotForRequest, expectedRequestId);

            var matched = answering.FirstOrDefault(d => IsAssertionConsumerService(d.Recipient, assertionConsumerServiceUrls));
            if (matched == null)
            {
                var received = string.Join(", ", answering.Select(d => d.Recipient ?? "(none)"));
                return string.Format(Resources.AssertionRecipientMismatch, received, string.Join(", ", assertionConsumerServiceUrls));
            }

            if (!matched.NotOnOrAfter.HasValue)
                return Resources.AssertionNotOnOrAfterMissing;

            confirmation = matched;
            return null;
        }

        private static bool IsAssertionConsumerService(string recipient, ICollection<Uri> assertionConsumerServiceUrls)
        {
            return Uri.TryCreate(recipient, UriKind.Absolute, out var recipientUrl) && assertionConsumerServiceUrls.Contains(recipientUrl);
        }

        /// <summary>
        /// The assertion consumer service URLs, as published in the service provider's metadata.
        /// </summary>
        internal static ICollection<Uri> AssertionConsumerServiceUrls(ServiceProviderElement serviceProvider)
        {
            return serviceProvider.serviceEndpoints
                .Where(e => e.endpointType == EndpointType.SIGNON)
                .Select(serviceProvider.GetEndpointUrl)
                .ToList();
        }

        /// <summary>
        /// Remembers the ID of an accepted assertion until it can no longer be valid, so that it is accepted only once.
        /// The cache is per process; the signed InResponseTo ties an assertion to one session across servers.
        /// </summary>
        /// <returns>false if the ID is already remembered: the assertion has been used before.</returns>
        internal static bool TryRegisterAssertion(string assertionId, DateTime validUntil)
        {
            return HttpRuntime.Cache.Add(ReplayCacheKeyPrefix + assertionId, string.Empty, null, validUntil,
                Cache.NoSlidingExpiration, CacheItemPriority.NotRemovable, null) == null;
        }

        private void DoLogin(HttpContext context, Saml20Assertion assertion)
        {
            SessionStore.RotateSessionId();
            SessionStore.AssociateUserIdWithCurrentSession(assertion.Subject.Value);

            // The assertion is what keeps the session alive. If it is ever removed ... the session will appear as removed in the SessionStoreProvider because Saml20AssertionLite is the only thing kept in session store when login flow is completed..
            SessionStore.CurrentSession[SessionConstants.Saml20AssertionLite] = Saml20AssertionLite.ToLite(assertion);
            SessionStore.CurrentSession[SessionConstants.ExpectedNsisLoa] = null;

            if (Trace.ShouldTrace(TraceEventType.Information))
            {
                Trace.TraceData(TraceEventType.Information, string.Format(Tracing.Login, assertion.Subject.Value, assertion.SessionIndex, assertion.Subject.Format));
            }

            string assuranceLevel = GetNsisLoa(assertion) ?? GetAssuranceLevel(assertion) ?? "(Unknown)";

            AuditLogging.logEntry(Direction.IN, Operation.LOGIN, string.Format("Subject: {0} NameIDFormat: {1}  Level of assurance: {2}  Session timeout in minutes: {3}", assertion.Subject.Value, assertion.Subject.Format, assuranceLevel, FederationConfig.GetConfig().SessionTimeout));

            foreach (IAction action in Actions.Actions.GetActions())
            {
                Trace.TraceMethodCalled(action.GetType(), "LoginAction()");

                action.LoginAction(this, context, assertion);

                Trace.TraceMethodDone(action.GetType(), "LoginAction()");
            }
        }

        /// <summary>
        /// Retrieves the assurance level (OIOSAML 2) from the assertion.
        /// </summary>
        /// <returns>Returns the assurance level or null if it has not been defined.</returns>
        private string GetAssuranceLevel(Saml20Assertion assertion)
        {
            foreach (var attribute in assertion.Attributes)
            {
                if (attribute.Name == DKSaml20AssuranceLevelAttribute.NAME
                    && attribute.AttributeValue != null
                    && attribute.AttributeValue.Length > 0)
                    return attribute.AttributeValue[0];
            }

            return null;
        }

        /// <summary>
        /// Retrieves the NSIS level of assurance from the assertion.
        /// </summary>
        /// <returns>Returns the NSIS LoA or null if it has not been defined.</returns>
        private string GetNsisLoa(Saml20Assertion assertion)
        {
            foreach (var attribute in assertion.Attributes)
            {
                if (attribute.Name == DKSaml20NsisLoaAttribute.NAME
                    && attribute.AttributeValue != null
                    && attribute.AttributeValue.Length > 0)
                    return attribute.AttributeValue[0];
            }

            return null;
        }

        private void TransferClient(IDPEndPoint idpEndpoint, Saml20AuthnRequest request, HttpContext context)
        {
            AuditLogging.AssertionId = request.ID;
            AuditLogging.IdpId = idpEndpoint.Id;

            // Determine which endpoint to use from the configuration file or the endpoint metadata.
            IDPEndPointElement destination = DetermineEndpointConfiguration(SAMLBinding.REDIRECT, idpEndpoint.SSOEndpoint, idpEndpoint.metadata.SSOEndpoints());
            request.Destination = destination.Url;
            var httpRequest = context.Request;
            
            // handle AppSwitch parameter.
            string appSwitchPlatform = httpRequest.Params[AppSwitchPlatform];
            if (!string.IsNullOrWhiteSpace(appSwitchPlatform))
            {
                var canParse = Enum.TryParse(appSwitchPlatform, true, out Platform queryStringPlatform);
                if (!canParse)
                {
                    string errorMessage = Resources.AppSwitchReturnUrlRequired;
                    AuditLogging.logEntry(Direction.IN, Operation.AUTHNREQUEST_POST, errorMessage);
                    HandleError(context, errorMessage);
                    return;
                }
                var appSwitchReturnUrl = SAML20FederationConfig.GetConfig().FindAppSwitchReturnUrlForPlatform(queryStringPlatform);
                if (string.IsNullOrWhiteSpace(appSwitchReturnUrl))
                {
                    string errorMessage = Resources.AppSwitchPlatformInvalid;
                    AuditLogging.logEntry(Direction.IN, Operation.AUTHNREQUEST_POST, errorMessage);
                    HandleError(context, errorMessage);
                    return;
                }
                
                var appSwitch = new AppSwitch
                {
                    Platform = (AppSwitchPlatform)Enum.Parse(typeof(AppSwitchPlatform), appSwitchPlatform),
                    ReturnURL = appSwitchReturnUrl
                };
                
                 var appSwitchXml = appSwitch.ToXmlElement(request.GetXml());
                 request.Request.Extensions = new Extensions {Any = new [] {appSwitchXml }};
            }
            
            bool isPassive;
            string isPassiveAsString = httpRequest.Params[IDPIsPassive];
            if (bool.TryParse(isPassiveAsString, out isPassive))
            {
                request.IsPassive = isPassive;
            }

            var requestContextItems = new List<(string value, ItemsChoiceType7 type)>();
            string demandedNsisLoa = null;
            if (!string.IsNullOrEmpty(context.Request.Params[NsisLoa]))
            {
                var demandedLevelOfAssurance = context.Request.Params[NsisLoa];

                // A demanded LoA can only raise the configured minimum.
                var configuredNsisLoa = SAML20FederationConfig.GetConfig().MinimumNsisLoa;
                var demandError = DemandedNsisLoaError(demandedLevelOfAssurance, configuredNsisLoa);
                if (demandError != null)
                {
                    HandleError(context, demandError, demandedLevelOfAssurance, configuredNsisLoa);
                    return;
                }

                requestContextItems.Add((DKSaml20NsisLoaAttribute.NAME + "/" + demandedLevelOfAssurance, ItemsChoiceType7.AuthnContextClassRef));
                demandedNsisLoa = demandedLevelOfAssurance;

                Trace.TraceData(TraceEventType.Information, string.Format(Tracing.DemandingLevelOfAssurance, demandedLevelOfAssurance));
            }

            if (!string.IsNullOrEmpty(context.Request.Params[Profile]))
            {
                var demandedProfile = context.Request.Params[Profile];

                if (!new[] { "Professional", "Person" }.Contains(demandedProfile))
                {
                    HandleError(context, Resources.DemandingProfileError, demandedProfile);
                    return;
                }
                requestContextItems.Add(("https://data.gov.dk/eid/" + demandedProfile, ItemsChoiceType7.AuthnContextClassRef));

                Trace.TraceData(TraceEventType.Information, string.Format(Tracing.DemandingProfile, demandedProfile));
            }
            if (requestContextItems.Count > 0)
            {
                request.Request.RequestedAuthnContext = new RequestedAuthnContext();
                request.Request.RequestedAuthnContext.Comparison = AuthnContextComparisonType.minimum;
                request.Request.RequestedAuthnContext.ComparisonSpecified = true;
                request.Request.RequestedAuthnContext.ItemsElementName = requestContextItems.Select(x => x.type).ToArray();
                request.Request.RequestedAuthnContext.Items = requestContextItems.Select(x => x.value).ToArray();
            }

            if (idpEndpoint.IsPassive)
                request.IsPassive = true;

            bool forceAuthn;
            string forceAuthnAsString = httpRequest.Params[IDPForceAuthn];
            if (bool.TryParse(forceAuthnAsString, out forceAuthn))
            {
                request.ForceAuthn = forceAuthn;
            }

            if (idpEndpoint.ForceAuthn)
                request.ForceAuthn = true;

            if (idpEndpoint.SSOEndpoint != null)
            {
                if (!string.IsNullOrEmpty(idpEndpoint.SSOEndpoint.ForceProtocolBinding))
                {
                    request.ProtocolBinding = idpEndpoint.SSOEndpoint.ForceProtocolBinding;
                }
            }

            AuthnRequestAppenderFactory.GetAppender()?.AppendAction(request, context.Request);

            //Save request message id and the IdP to session, together with the demanded LoA to verify the assertion against
            SessionStore.CurrentSession[SessionConstants.ExpectedInResponseTo] = request.ID;
            SessionStore.CurrentSession[SessionConstants.ExpectedIdpId] = idpEndpoint.Id;
            SessionStore.CurrentSession[SessionConstants.ExpectedNsisLoa] = demandedNsisLoa;

            var shaHashingAlgorithm = SignatureProviderFactory.ValidateShaHashingAlgorithm(idpEndpoint.ShaHashingAlgorithm);
            if (destination.Binding == SAMLBinding.REDIRECT)
            {
                Trace.TraceData(TraceEventType.Information, string.Format(Tracing.SendAuthnRequest, Saml20Constants.ProtocolBindings.HTTP_Redirect, idpEndpoint.Id));

                HttpRedirectBindingBuilder builder = new HttpRedirectBindingBuilder();
                builder.signingKey = _certificate.GetRSAPrivateKey();
                builder.Request = request.GetXml().OuterXml;
                builder.ShaHashingAlgorithm = shaHashingAlgorithm;
                string s = request.Destination + "?" + builder.ToQuery();

                AuditLogging.logEntry(Direction.OUT, Operation.AUTHNREQUEST_REDIRECT, "Redirecting user to IdP for authentication", builder.Request);

                context.Response.Redirect(s, true);
                return;
            }

            if (destination.Binding == SAMLBinding.POST)
            {
                Trace.TraceData(TraceEventType.Information, string.Format(Tracing.SendAuthnRequest, Saml20Constants.ProtocolBindings.HTTP_Post, idpEndpoint.Id));

                HttpPostBindingBuilder builder = new HttpPostBindingBuilder(destination);
                //Honor the ForceProtocolBinding and only set this if it's not already set
                if (string.IsNullOrEmpty(request.ProtocolBinding))
                    request.ProtocolBinding = Saml20Constants.ProtocolBindings.HTTP_Post;
                XmlDocument req = request.GetXml();
                var signingCertificate = FederationConfig.GetConfig().GetFirstValidCertificate();
                var signatureProvider = SignatureProviderFactory.CreateFromShaHashingAlgorithmName(shaHashingAlgorithm);
                signatureProvider.SignAssertion(req, request.ID, signingCertificate);
                builder.Request = req.OuterXml;
                AuditLogging.logEntry(Direction.OUT, Operation.AUTHNREQUEST_POST);

                builder.GetPage().ProcessRequest(context);
                return;
            }

            if (destination.Binding == SAMLBinding.ARTIFACT)
            {
                Trace.TraceData(TraceEventType.Information, string.Format(Tracing.SendAuthnRequest, Saml20Constants.ProtocolBindings.HTTP_Artifact, idpEndpoint.Id));

                HttpArtifactBindingBuilder builder = new HttpArtifactBindingBuilder(context);

                //Honor the ForceProtocolBinding and only set this if it's not already set
                if (string.IsNullOrEmpty(request.ProtocolBinding))
                    request.ProtocolBinding = Saml20Constants.ProtocolBindings.HTTP_Artifact;
                AuditLogging.logEntry(Direction.OUT, Operation.AUTHNREQUEST_REDIRECT_ARTIFACT);

                builder.RedirectFromLogin(idpEndpoint, destination, request);
            }

            HandleError(context, Resources.BindingError);
        }

    }
        
}