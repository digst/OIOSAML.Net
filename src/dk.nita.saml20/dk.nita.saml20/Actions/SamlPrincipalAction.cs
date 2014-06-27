using System.Web;
using System.Web.Security;
using dk.nita.saml20.session;
using dk.nita.saml20.identity;
using dk.nita.saml20.protocol;
using System.Security.Principal;
using dk.nita.saml20.Identity;

namespace dk.nita.saml20.Actions
{
    /// <summary>
    /// Sets the SamlPrincipal on the current http context
    /// </summary>
    public class SamlPrincipalAction : IAction
    {

        /// <summary>
        /// The default action name
        /// </summary>
        public const string ACTION_NAME = "SetSamlPrincipal";

        /// <summary>
        /// Action performed during login.
        /// </summary>
        /// <param name="handler">The handler initiating the call.</param>
        /// <param name="context">The current http context.</param>
        /// <param name="assertion">The saml assertion of the currently logged in user.</param>
        public void LoginAction(AbstractEndpointHandler handler, HttpContext context, Saml20Assertion assertion)
        {
            FormsAuthentication.SetAuthCookie(Saml20PrincipalCache.GetPrincipal().Identity.Name, false);  
        }

        /// <summary>
        /// Action performed during logout.
        /// </summary>
        /// <param name="handler">The handler.</param>
        /// <param name="context">The context.</param>
        /// <param name="IdPInitiated">During IdP initiated logout some actions such as redirecting should not be performed</param>
        public void LogoutAction(AbstractEndpointHandler handler, HttpContext context, bool IdPInitiated)
        {
            FormsAuthentication.SignOut();
            HttpContext.Current.User = new GenericPrincipal(new GenericIdentity(string.Empty), null); // Makes User.Identity.IsAuthenticated false in the current request.
        }

        /// <summary>
        /// <see cref="IAction.SoapLogoutAction"/>
        /// </summary>
        public void SoapLogoutAction(AbstractEndpointHandler handler, HttpContext context, string userId)
        {
            // Do nothing
        }

        private string _name;

        /// <summary>
        /// Gets or sets the name of the action.
        /// </summary>
        /// <value>The name.</value>
        public string Name
        {
            get
            {
                return string.IsNullOrEmpty(_name) ? ACTION_NAME : _name;
            }
            set { _name = value; }
        }
    }
}
