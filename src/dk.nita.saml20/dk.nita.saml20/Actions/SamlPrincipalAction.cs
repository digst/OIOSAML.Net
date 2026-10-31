using System;
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
            // Like FormsAuthentication.SetAuthCookie, but the ticket is tied to the OIOSAML session and ends no later than the login.
            var now = DateTime.Now;
            var expiration = now.Add(FormsAuthentication.Timeout);
            var validUntil = Saml20PrincipalCache.GetSaml20AssertionLite()?.ValidUntil?.ToLocalTime();
            if (validUntil.HasValue && validUntil.Value < expiration)
                expiration = validUntil.Value;

            var ticket = new FormsAuthenticationTicket(2, Saml20PrincipalCache.GetPrincipal().Identity.Name, now, expiration, false,
                Saml20Identity.FormsTicketBinding(), FormsAuthentication.FormsCookiePath);
            var cookie = new HttpCookie(FormsAuthentication.FormsCookieName, FormsAuthentication.Encrypt(ticket))
            {
                HttpOnly = true,
                Secure = FormsAuthentication.RequireSSL,
                Path = FormsAuthentication.FormsCookiePath,
                SameSite = FormsAuthentication.CookieSameSite
            };
            if (FormsAuthentication.CookieDomain != null)
                cookie.Domain = FormsAuthentication.CookieDomain;
            context.Response.Cookies.Add(cookie);
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
