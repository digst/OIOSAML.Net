using System;
using System.Collections.Generic;
using System.Linq;
using dk.nita.saml20.config;
using dk.nita.saml20.Schema.Core;

namespace dk.nita.saml20.Session
{
    /// <summary>
    /// A lite version of <see cref="Saml20Assertion"/> that is serializable. This is necessary in order to be able to support a distributed cache implementation of <see cref="ISessionStoreProvider"/>
    /// </summary>
    [Serializable]
    public class Saml20AssertionLite
    {
        /// <summary>
        /// Issuer
        /// </summary>
        public string Issuer { get; set; }
        /// <summary>
        /// Subject
        /// </summary>
        public NameID Subject { get; set; }
        /// <summary>
        /// SessionIndex
        /// </summary>
        public string SessionIndex { get; set; }
        /// <summary>
        /// Attributes
        /// </summary>
        public List<SamlAttribute> Attributes { get; set; }
        /// <summary>
        /// The end of the login (UTC), however active the user is. Null for a session stored by an earlier version.
        /// </summary>
        public DateTime? ValidUntil { get; set; }

        internal static Saml20AssertionLite ToLite(Saml20Assertion assertion)
        {
            var assertionLite = new Saml20AssertionLite();
            
            assertionLite.Issuer = assertion.Issuer;
            assertionLite.Subject = assertion.Subject;
            assertionLite.SessionIndex = assertion.SessionIndex;
            assertionLite.Attributes = assertion.Attributes;

            var authnStatement = assertion.Assertion.GetAuthnStatements().FirstOrDefault();
            assertionLite.ValidUntil = GetValidUntil(authnStatement?.AuthnInstant, authnStatement?.SessionNotOnOrAfter, DateTime.UtcNow,
                TimeSpan.FromMinutes(FederationConfig.GetConfig().MaximumSessionLength));

            return assertionLite;
        }

        /// <summary>
        /// The end of a login: the authentication time plus the maximum session length, or the IdP's SessionNotOnOrAfter if earlier.
        /// </summary>
        internal static DateTime GetValidUntil(DateTime? authnInstant, DateTime? sessionNotOnOrAfter, DateTime now, TimeSpan maximumSessionLength)
        {
            var validUntil = (authnInstant ?? now) + maximumSessionLength;
            return sessionNotOnOrAfter.HasValue && sessionNotOnOrAfter.Value < validUntil ? sessionNotOnOrAfter.Value : validUntil;
        }
    }
}
