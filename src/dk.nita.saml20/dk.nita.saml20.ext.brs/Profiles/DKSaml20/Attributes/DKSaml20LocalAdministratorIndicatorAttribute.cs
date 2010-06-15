using System;
using System.Collections.Generic;
using System.Text;
using dk.nita.saml20.Profiles.DKSaml20.Attributes;
using dk.nita.saml20.Schema.Core;

namespace dk.nita.saml2.ext.brs.Profiles.DKSaml20.Attributes
{
    public class DKSaml20LocalAdministratorIndicatorAttribute : DKSaml20Attribute
    {
        /// <summary>
        /// Attribute name
        /// </summary>
        public const string NAME = "dk.gov.virk.saml.attribute.LocalAdministratorIndicator";
        /// <summary>
        /// Friendly name
        /// </summary>
        public const string FRIENDLYNAME = "LocalAdministratorIndicator";

        /// <summary>
        /// Creates an attribute with the specified value.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        public static SamlAttribute Create(string value)
        {
            return Create(NAME, FRIENDLYNAME, value);
        }
    }
}
