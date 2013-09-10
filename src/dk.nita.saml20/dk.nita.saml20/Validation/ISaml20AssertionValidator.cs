using System;
using dk.nita.saml20.Schema.Core;

namespace dk.nita.saml20.Validation
{
    internal interface ISaml20AssertionValidator
    {
        void ValidateAssertion(Assertion assertion);
        void ValidateTimeRestrictions(Assertion assertion, TimeSpan allowedClockSkew);
    }
}