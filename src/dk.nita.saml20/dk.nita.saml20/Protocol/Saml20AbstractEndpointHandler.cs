using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Web;
using dk.nita.saml20.Bindings;
using dk.nita.saml20.config;
using dk.nita.saml20.Logging;
using dk.nita.saml20.Properties;
using dk.nita.saml20.Schema.Protocol;
using dk.nita.saml20.Utils;
using Trace=dk.nita.saml20.Utils.Trace;

namespace dk.nita.saml20.protocol
{
    /// <summary>
    /// Base class for all SAML20 specific endpoints.
    /// </summary>
    public abstract class Saml20AbstractEndpointHandler : AbstractEndpointHandler
    {

        /// <summary>
        /// Parameter name for idp choice
        /// </summary>
        public const string IDPChoiceParameterName = "cidp";
        /// <summary>
        /// Parameter name for idp choice
        /// </summary>
        public const string IDPForceAuthn = "forceAuthn";
        /// <summary>
        /// Parameter name for idp choice
        /// </summary>
        public const string IDPIsPassive = "isPassive";
        /// <summary>
        /// Parameter name for level of assurance
        /// </summary>
        public const string NSISLevel = "levelOfAssurance";
        /// <summary>
        /// Parameter name for profile type (Person/Professional)
        /// </summary>
        public const string Profile = "profile";
        /// <summary>
        /// Determines if configuration has been validated
        /// </summary>
        public static bool validated = false;

        /// <summary>
        /// Enables processing of HTTP Web requests by a custom HttpHandler that implements the <see cref="T:System.Web.IHttpHandler"/> interface.
        /// </summary>
        /// <param name="context">An <see cref="T:System.Web.HttpContext"/> object that provides references to the intrinsic server objects (for example, Request, Response, Session, and Server) used to service HTTP requests.</param>
        public sealed override void ProcessRequest(HttpContext context)
        {
            try
            {
                CheckConfiguration(context);
                Handle(context);
            }
            catch (Exception ex)
            {
                HandleError(context, ex);
            }
        }

        /// <summary>
        /// Checks the configuration elements and redirects to an error page if something is missing or wrong.
        /// </summary>
        /// <param name="ctx"></param>
        private void CheckConfiguration(HttpContext ctx)
        {
            if (validated)
                return;

            string errorMessage;
            validated = BindingUtility.ValidateConfiguration(out errorMessage);
            if (!validated)            
                HandleError(ctx, errorMessage);                        
        }

        /// <summary>
        /// Abstract handler function
        /// </summary>
        /// <param name="ctx">The context.</param>
        protected abstract void Handle(HttpContext ctx);

        /// <summary>
        /// Handles the selection of an IDP. If only one IDP is found, the user is automatically redirected to it.
        /// If several are found, and nothing indicates to which one the user should be sent, this method returns null.
        /// </summary>
        public IDPEndPoint RetrieveIDP(HttpContext context)
        {
            SAML20FederationConfig config = SAML20FederationConfig.GetConfig();
            
            //If idpChoice is set, use it value
            if (!string.IsNullOrEmpty(context.Request.Params[IDPChoiceParameterName]))
            {
                AuditLogging.logEntry(Direction.IN, Operation.DISCOVER,
                                      "Using IDPChoiceParamater: " + context.Request.Params[IDPChoiceParameterName]);
                IDPEndPoint endPoint = config.FindEndPoint(context.Request.Params[IDPChoiceParameterName]);
                if (endPoint != null)                
                    return endPoint;                
            }

            //If we have a common domain cookie, use it's value
            //It must have been returned from the local common domain cookie reader endpoint.
            if (!string.IsNullOrEmpty(context.Request.QueryString["_saml_idp"]))
            {
                CommonDomainCookie cdc = new CommonDomainCookie(context.Request.QueryString["_saml_idp"]);
                if (cdc.IsSet)
                {
                    IDPEndPoint endPoint = config.FindEndPoint(cdc.PreferredIDP);
                    if (endPoint != null)
                    {
                        if (Trace.ShouldTrace(TraceEventType.Information))
                            Trace.TraceData(TraceEventType.Information, "IDP read from Common Domain Cookie: " + cdc.PreferredIDP);
                    
                        return endPoint;
                    }

                    AuditLogging.logEntry(Direction.IN, Operation.DISCOVER, "Invalid IdP in Common Domain Cookie, IdP not found in list of IdPs: " + cdc.PreferredIDP);
                }
            }

            //If there is only one configured IDPEndPoint lets just use that
            if (config.IDPEndPoints.Count == 1 && config.IDPEndPoints[0].metadata != null)
            {
                AuditLogging.logEntry(Direction.IN, Operation.DISCOVER, "No IdP selected in Common Domain Cookie, using default IdP: " + config.IDPEndPoints[0].Name);
                return config.IDPEndPoints[0];
            }

            // If one of the endpoints are marked with default, use that one
            var defaultIdp = config.Endpoints.IDPEndPoints.Find(idp => idp.Default);
            if(defaultIdp != null)
            {
                if (Trace.ShouldTrace(TraceEventType.Information))
                    Trace.TraceData(TraceEventType.Information, "Using IdP marked as default: " + defaultIdp.Id);

                return defaultIdp;
            }

            // In case an Idp selection url has been configured, redirect to that one.
            if(!string.IsNullOrEmpty(config.Endpoints.idpSelectionUrl))
            {
                if (Trace.ShouldTrace(TraceEventType.Information))
                    Trace.TraceData(TraceEventType.Information, "Redirecting to idpSelectionUrl for selection of IDP: " + config.Endpoints.idpSelectionUrl);

                context.Response.Redirect(config.Endpoints.idpSelectionUrl);
            }

            // If an IDPSelectionEvent handler is present, request the handler for an IDP endpoint to use.
            var idpEndpoint = IDPSelectionUtil.InvokeIDPSelectionEventHandler(config.Endpoints);
            if(idpEndpoint != null)
            {
                return idpEndpoint;
            }

            return null;
        }

        /// <summary>
        /// Looks through the Identity Provider configurations and 
        /// </summary>
        public IDPEndPoint RetrieveIDPConfiguration(string IDPId)
        {
            if (IDPId == null) return null;
            SAML20FederationConfig config = SAML20FederationConfig.GetConfig();
            return config.FindEndPoint(IDPId);
        }

        /// <summary>
        /// Utility function for error handling.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="status">The status.</param>
        protected void HandleError(HttpContext context, Status status)
        {
            string errorMessage = string.Format("ErrorCode: {0}. Message: {1}.", status.StatusCode.Value, status.StatusMessage);

            if(status.StatusCode.SubStatusCode != null){
                switch (status.StatusCode.SubStatusCode.Value)
                {
                    case Saml20Constants.StatusCodes.AuthnFailed:
                        HandleError(context, errorMessage, true);
                        break;
                    default:
                        HandleError(context, errorMessage, false);
                        break;
                }
            } else {
                HandleError(context, errorMessage, false);
            }                
        }

        /// <summary>
        /// Determine which endpoint to use based on the protocol defaults, configuration data and metadata.
        /// </summary>
        /// <param name="defaultBinding">The binding to use if none has been specified in the configuration and the metadata allows all bindings.</param>
        /// <param name="config">The endpoint as described in the configuration. May be null.</param>
        /// <param name="metadata">A list of endpoints of the given type (eg. SSO or SLO) that the metadata contains. </param>        
        internal static IDPEndPointElement DetermineEndpointConfiguration(SAMLBinding defaultBinding, IDPEndPointElement config, List<IDPEndPointElement> metadata)
        {
            IDPEndPointElement result = new IDPEndPointElement();
            result.Binding = defaultBinding;

            // Determine which binding to use.
            if (config != null)
            {
                result.Binding = config.Binding;
            } else {
                // Verify that the metadata allows the default binding.
                bool allowed = metadata.Exists(delegate(IDPEndPointElement el) { return el.Binding == defaultBinding; });
                if (!allowed)
                {
                    if (result.Binding == SAMLBinding.POST)
                        result.Binding = SAMLBinding.REDIRECT;
                    else
                        result.Binding = SAMLBinding.POST;
                }                    
            }

            if (config != null && !string.IsNullOrEmpty(config.Url))
            {
                result.Url = config.Url;
            } else
            {
                IDPEndPointElement endpoint =
                    metadata.Find(delegate(IDPEndPointElement el) { return el.Binding == result.Binding; });

                if (endpoint == null)
                    throw new ConfigurationErrorsException(
                        String.Format("No IdentityProvider supporting SAML binding {0} found in metadata",
                                      result.Binding));

                result.Url = endpoint.Url;
            }

            return result;
        }

    }
}