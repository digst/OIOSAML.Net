using System;
using System.Collections.Generic;
using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.session;

namespace dk.nita.saml20.Session
{
    /// <summary>
    /// A lite version of <see cref="Saml20Assertion"/> that is serializable. This is necessary in order to be able to support a distributed cache implementation of <see cref="ISessions"/>
    /// </summary>
    [Serializable]
    class Saml20AssertionLite
    {
        internal string Issuer { get; set; }
        internal NameID Subject { get; set; }
        internal string SessionIndex { get; set; }
        internal List<SamlAttribute> Attributes { get; set; }


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
