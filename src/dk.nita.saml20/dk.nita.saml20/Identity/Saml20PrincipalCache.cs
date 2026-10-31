using System;
using System.Collections.Generic;
using System.Security.Principal;
using dk.nita.saml20.Session;
using dk.nita.saml20.session;
using dk.nita.saml20.identity;
using dk.nita.saml20.config;

namespace dk.nita.saml20.Identity
{
    /// <summary>
    /// 
    /// </summary>
    internal class Saml20PrincipalCache
    {
        /// <summary>
        /// Gets the principal.
        /// </summary>
        /// <returns></returns>
        internal static IPrincipal GetPrincipal()
        {
            var saml20Assertion = GetSaml20AssertionLite();
            if (saml20Assertion != null)
                return Saml20Identity.InitSaml20Identity(saml20Assertion);
            return null;
        }

        /// <summary>
        /// Gets the principal.
        /// </summary>
        /// <returns></returns>
        internal static Saml20AssertionLite GetSaml20AssertionLite()
        {
            var session = SessionStore.CurrentSession;
            var assertion = session?[SessionConstants.Saml20AssertionLite] as Saml20AssertionLite;
            if (assertion?.ValidUntil != null &&
                DateTime.UtcNow >= assertion.ValidUntil.Value.AddMinutes(FederationConfig.GetConfig().AllowedClockSkewMinutes))
            {
                // The login has reached its maximum length.
                session[SessionConstants.Saml20AssertionLite] = null;
                return null;
            }

            return assertion;
        }
    }
}
