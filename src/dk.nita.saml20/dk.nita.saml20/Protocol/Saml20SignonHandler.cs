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

                HandleSOAP(context, context.Request.InputStream);
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
            Stream inputStream = builder.ResolveArtifact();
            HandleSOAP(context, inputStream);
        }

        private void HandleSOAP(HttpContext context, Stream inputStream)
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

                Status status = parser.ArtifactResponse.Status;
                if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
                {
                    HandleError(context, status);
                    AuditLogging.logEntry(Direction.IN, Operation.ARTIFACTRESOLVE, string.Format("Illegal status for ArtifactResponse {0} expected 'Success', msg: {1}", status.StatusCode.Value, parser.SamlMessage));
                    return;
                }
                if (parser.ArtifactResponse.Any.LocalName == Response.ELEMENT_NAME)
                {
                    bool isEncrypted;
                    XmlElement assertion = GetAssertion(parser.ArtifactResponse.Any, out isEncrypted);
                    if (assertion == null)
                        HandleError(context, "Missing assertion");
                    if (isEncrypted)
                    {
                        HandleEncryptedAssertion(context, assertion);
                    }
                    else
                    {
                        HandleAssertion(context, assertion);
                    }

                }
                else
                {
                    AuditLogging.logEntry(Direction.IN, Operation.ARTIFACTRESOLVE, string.Format("Unsupported payload message in ArtifactResponse: {0}, msg: {1}", parser.ArtifactResponse.Any.LocalName, parser.SamlMessage));
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
                    AuditLogging.logEntry(Direction.IN, Operation.ARTIFACTRESOLVE, string.Format("Unsupported SamlMessage element: {0}, msg: {1}", parser.SamlMessageName, parser.SamlMessage));
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

        private Status GetStatusElement(XmlDocument doc)
        {
            XmlElement statElem =
                (XmlElement)doc.GetElementsByTagName(Status.ELEMENT_NAME, Saml20Constants.PROTOCOL)[0];

            return Serialization.DeserializeFromXmlString<Status>(statElem.OuterXml);
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

            AuditLogging.logEntry(Direction.IN, Operation.LOGIN, "Received SAMLResponse: " + doc.OuterXml);

            try
            {

                var inResponseToAttribute = doc.DocumentElement.Attributes["InResponseTo"];

                if (inResponseToAttribute == null)
                    throw new Saml20Exception("Received a response message that did not contain an InResponseTo attribute");

                string inResponseTo = inResponseToAttribute.Value;

                CheckReplayAttack(context, inResponseTo);

                Status status = GetStatusElement(doc);

                if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
                {
                    if (status.StatusCode.Value == Saml20Constants.StatusCodes.Responder && status.StatusCode.SubStatusCode != null && Saml20Constants.StatusCodes.NoPassive == status.StatusCode.SubStatusCode.Value)
                        HandleError(context, Resources.SamlNoPassiveError);

                    HandleError(context, status);
                    return;
                }

                // Determine whether the assertion should be decrypted before being validated.

                bool isEncrypted;
                XmlElement assertion = GetAssertion(doc.DocumentElement, out isEncrypted);
                if (isEncrypted)
                {
                    assertion = GetDecryptedAssertion(assertion).Assertion.DocumentElement;
                }

                // Check if an encoding-override exists for the IdP endpoint in question
                string issuer = GetIssuer(assertion);
                IDPEndPoint endpoint = RetrieveIDPConfiguration(issuer);
                if (!string.IsNullOrEmpty(endpoint.ResponseEncoding))
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
                        assertion = GetAssertion(doc1.DocumentElement, out isEncrypted);
                    }
                }

                HandleAssertion(context, assertion);
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

        private static void CheckReplayAttack(HttpContext context, string inResponseTo)
        {
            if (string.IsNullOrEmpty(inResponseTo))
                throw new Saml20Exception("Empty InResponseTo from IdP is not allowed.");

            var expectedInResponseToSessionState = SessionStore.CurrentSession[SessionConstants.ExpectedInResponseTo];
            SessionStore.CurrentSession[SessionConstants.ExpectedInResponseTo] = null; // Ensure that no more responses can be received.

            string expectedInResponseTo = expectedInResponseToSessionState?.ToString();
            if (string.IsNullOrEmpty(expectedInResponseTo))
                throw new Saml20Exception("Expected InResponseTo not found in current session.");

            if (inResponseTo != expectedInResponseTo)
            {
                AuditLogging.logEntry(Direction.IN, Operation.LOGIN, string.Format("Unexpected value {0} for InResponseTo, expected {1}, possible replay attack!", inResponseTo, expectedInResponseTo));
                throw new Saml20Exception("Replay attack.");
            }
        }

        private static XmlDocument GetDecodedSamlResponse(HttpContext context, Encoding encoding)
        {
            string base64 = context.Request.Params["SAMLResponse"];

            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = null;
            doc.PreserveWhitespace = true;
            string samlResponse = encoding.GetString(Convert.FromBase64String(base64));
            if (Trace.ShouldTrace(TraceEventType.Information))
                Trace.TraceData(TraceEventType.Information, "Decoded SAMLResponse", samlResponse);

            doc.LoadXml(samlResponse);
            return doc;
        }

        /// <summary>
        /// Decrypts an encrypted assertion, and sends the result to the HandleAssertion method.
        /// </summary>
        private void HandleEncryptedAssertion(HttpContext context, XmlElement elem)
        {
            Trace.TraceMethodCalled(GetType(), "HandleEncryptedAssertion()");
            Saml20EncryptedAssertion decryptedAssertion = GetDecryptedAssertion(elem);
            HandleAssertion(context, decryptedAssertion.Assertion.DocumentElement);
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
                Saml20EncryptedAssertion decryptedAssertion = new Saml20EncryptedAssertion((RSA)certificate.PrivateKey);
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
                catch (Exception)
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

                    throw;
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
        private void HandleAssertion(HttpContext context, XmlElement elem)
        {
            Trace.TraceMethodCalled(GetType(), "HandleAssertion");

            string issuer = GetIssuer(elem);

            IDPEndPoint endp = RetrieveIDPConfiguration(issuer);

            AuditLogging.IdpId = endp.Id;

            PreHandleAssertion(context, elem, endp);

            bool quirksMode = false;

            if (endp != null)
            {
                quirksMode = endp.QuirksMode;
            }

            Saml20Assertion assertion = new Saml20Assertion(elem, null, quirksMode);
            assertion.Validate(DateTime.UtcNow);

            if (endp == null || endp.metadata == null)
            {
                AuditLogging.logEntry(Direction.IN, Operation.AUTHNREQUEST_POST,
                          "Unknown login IDP, assertion: " + elem);

                HandleError(context, Resources.UnknownLoginIDP);
                return;
            }

            if (!endp.OmitAssertionSignatureCheck)
            {
                IEnumerable<string> validationFailures;
                if (!assertion.CheckSignature(GetTrustedSigners(endp.metadata.GetKeys(KeyTypes.signing), endp, out validationFailures)))
                {
                    AuditLogging.logEntry(Direction.IN, Operation.AUTHNREQUEST_POST,
                    "Invalid signature, assertion: " + elem);

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

            if (assertion.IsExpired())
            {
                AuditLogging.logEntry(Direction.IN, Operation.AUTHNREQUEST_POST,
                "Assertion expired, assertion: " + elem.OuterXml);

                HandleError(context, Resources.AssertionExpired);
                return;
            }

            if (!ValidateLoA(context, assertion, elem)) return;

            CheckConditions(context, assertion);
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
            // If AssuranceLevel is allowed, and it's present in assertion, validate.
            var allowAL = SAML20FederationConfig.GetConfig().AllowAssuranceLevel;
            var assertionAL = GetAssuranceLevel(assertion);
            if(allowAL && assertionAL != null)
            {
                return ValidateAssuranceLevel(assertionAL, context, assertionXml);
            }

            // If NSIS LoA is missing, invalidate.
            var assertionNsisLoa = GetNsisLoa(assertion);
            if (assertionNsisLoa == null)
            {
                AuditLogging.logEntry(Direction.IN, Operation.AUTHNREQUEST_POST, Resources.NsisLoaMissing + " Assertion: " + assertionXml.OuterXml);
                HandleError(context, Resources.NsisLoaMissing);
                return false;
            }

            return ValidateNsisLoa(assertionNsisLoa, context, assertionXml);
        }

        /// <summary>
        /// Validates if a NSIS LoA is equals to or higher than a minimum required LoA.
        /// If validation fails, response is modified to display an error page.
        /// </summary>
        /// <returns>True if valid, otherwise false (and modified response).</returns>
        private bool ValidateNsisLoa(string loa, HttpContext context, XmlElement assertionXml)
        {
            var demandedNsisLoa = SessionStore.CurrentSession[SessionConstants.ExpectedNsisLoa]?.ToString();
            var minLoa = demandedNsisLoa ?? SAML20FederationConfig.GetConfig().MinimumNsisLoa;
            
            if (loa == minLoa) return true;
            
            switch (minLoa)
            {
                case "High" when loa != "High":
                case "Substantial" when loa != "High" && loa != "Substantial":
                    var msgTemplate = demandedNsisLoa != null ?
                        Resources.NsisLoaTooLowAccordingToDemand :
                        Resources.NsisLoaTooLow;
                    HandleLoaValidationError(msgTemplate, loa, demandedNsisLoa, context, assertionXml);
                    return false;
                default:
                    return true;
            }
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

        private void CheckConditions(HttpContext context, Saml20Assertion assertion)
        {
            if (assertion.IsOneTimeUse)
            {
                if (context.Cache[assertion.Id] != null)
                {
                    HandleError(context, Resources.OneTimeUseReplay);
                }
                else
                {
                    context.Cache.Insert(assertion.Id, string.Empty, null, assertion.NotOnOrAfter, Cache.NoSlidingExpiration);
                }
            }
        }

        private void DoLogin(HttpContext context, Saml20Assertion assertion)
        {
            SessionStore.AssociateUserIdWithCurrentSession(assertion.Subject.Value);

            // The assertion is what keeps the session alive. If it is ever removed ... the session will appear as removed in the SessionStoreProvider because Saml20AssertionLite is the only thing kept in session store when login flow is completed..
            SessionStore.CurrentSession[SessionConstants.Saml20AssertionLite] = Saml20AssertionLite.ToLite(assertion);

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
            if (!string.IsNullOrEmpty(context.Request.Params[NsisLoa]))
            {
                var demandedLevelOfAssurance = context.Request.Params[NsisLoa];
                if (!new[] { "Low", "Substantial", "High" }.Contains(demandedLevelOfAssurance))
                {
                    HandleError(context, Resources.DemandingLevelOfAssuranceError, demandedLevelOfAssurance);
                    return;
                }

                requestContextItems.Add((DKSaml20NsisLoaAttribute.NAME + "/" + demandedLevelOfAssurance, ItemsChoiceType7.AuthnContextClassRef));

                // Persist demanded LoA in session to be able to verify assertion
                SessionStore.CurrentSession[SessionConstants.ExpectedNsisLoa] = demandedLevelOfAssurance;

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

            //Save request message id to session
            SessionStore.CurrentSession[SessionConstants.ExpectedInResponseTo] = request.ID;

            var shaHashingAlgorithm = SignatureProviderFactory.ValidateShaHashingAlgorithm(idpEndpoint.ShaHashingAlgorithm);
            if (destination.Binding == SAMLBinding.REDIRECT)
            {
                Trace.TraceData(TraceEventType.Information, string.Format(Tracing.SendAuthnRequest, Saml20Constants.ProtocolBindings.HTTP_Redirect, idpEndpoint.Id));

                HttpRedirectBindingBuilder builder = new HttpRedirectBindingBuilder();
                builder.signingKey = _certificate.PrivateKey;
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