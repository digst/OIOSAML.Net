using System.Web;
using System.Security.Principal;
using dk.nita.saml20.Session;
using dk.nita.saml20.identity;

namespace dk.nita.saml20.Identity
{
    /// <summary>
    /// 
    /// </summary>
    internal class Saml20PrincipalCache
    {
        /// <summary>
        /// Adds the principal.
        /// </summary>
        /// <param name="principal">The principal.</param>
        internal static void AddPrincipal(IPrincipal principal)
        {
            SessionFactory.Session[SessionConstants.Saml20Identity] = principal;
        }

        /// <summary>
        /// Gets the principal.
        /// </summary>
        /// <returns></returns>
        internal static IPrincipal GetPrincipal()
        {
            return (IPrincipal) SessionFactory.Session[SessionConstants.Saml20Identity];
        }

        /// <summary>
        /// Clears this instance.
        /// </summary>
        internal static void Clear()
        {
            SessionFactory.Session.InvalidateKey(SessionConstants.Saml20Identity);
        }
    }
}
