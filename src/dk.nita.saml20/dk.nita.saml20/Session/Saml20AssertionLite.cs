using System;
using System.Collections.Generic;
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

        internal static Saml20AssertionLite ToLite(Saml20Assertion assertion)
        {
            var assertionLite = new Saml20AssertionLite();
            
            assertionLite.Issuer = assertion.Issuer;
            assertionLite.Subject = assertion.Subject;
            assertionLite.SessionIndex = assertion.SessionIndex;
            assertionLite.Attributes = assertion.Attributes;

            return assertionLite;
        }
    }
}
