using dk.nita.saml20.identity;
using dk.nita.saml20.Profiles.BasicPrivilegeProfile;
using dk.nita.saml20.Profiles.DKSaml20.Attributes;
using dk.nita.saml20.Schema.BasicPrivilegeProfile;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;

namespace dk.nita.saml20.Utils
{
    /// <summary>
    /// Helpers for converting between string and DateTime representations of UTC date-times
    /// and for enforcing the UTC-string-format demand for xml strings in Saml2.0
    /// </summary>
    internal static class Saml20Utils
    {
        public static DateTime FromUTCString(string value)
        {
            try
            {
                return XmlConvert.ToDateTime(value, XmlDateTimeSerializationMode.Utc);
            }
            catch (FormatException fe)
            {
                throw new Saml20FormatException("Invalid DateTime-string (non-UTC) found in saml:Assertion", fe);
            }
        }

        public static string ToUTCString(DateTime value)
        {
            return XmlConvert.ToString(value, XmlDateTimeSerializationMode.Utc);
        }

        /// <summary>
        /// A string value marked as REQUIRED in [SAML2.0std] must contain at least one non-whitespace character
        /// </summary>
        public static bool ValidateRequiredString(string reqString)
        {
            return !(String.IsNullOrEmpty(reqString) || reqString.Trim().Length == 0);
        }

        /// <summary>
        /// A string value marked as OPTIONAL in [SAML2.0std] must contain at least one non-whitespace character
        /// </summary>
        public static bool ValidateOptionalString(string optString)
        {
            if (optString != null)
                return ValidateRequiredString(optString);

            return true;
        }


        /// <summary>
        /// Make sure that the ID elements is at least 128 bits in length (SAML2.0 std section 1.3.4)
        /// </summary>
        public static bool ValidateIDString(string id)
        {
            if (id == null)
                return false;

            return id.Length >= 16;
        }

        /// <summary>
        /// Extracts the Basic privilege profile (simple or intermediate) from the saml attributes
        /// </summary>
        /// <param name="identity"></param>
        /// <returns></returns>
        public static IEnumerable<Privilege> GetBasicPrivilegeProfilePrivileges(Saml20Identity identity)
        {
            if (identity.HasAttribute(DKSaml20BasicPrivilegeProfileIntermediateAttribute.NAME))
            {
                var intermetiateProfiles = identity[DKSaml20BasicPrivilegeProfileIntermediateAttribute.NAME];
                foreach (var profile64 in intermetiateProfiles)
                {
                    var basicPrivilegeProfileXml = Encoding.UTF8.GetString(Convert.FromBase64String(profile64.AttributeValue[0]));
                    var basicPrivilegeProfile = Serialization.DeserializeFromXmlString<PrivilegeListType>(basicPrivilegeProfileXml);

                    foreach (var privilegeGroup in basicPrivilegeProfile.PrivilegeGroups)
                    {
                        foreach (var privilege in privilegeGroup.Privilege)
                        {
                            yield return new Privilege(privilegeGroup.Scope, privilege, privilegeGroup.Constraint.Select(x=>
                                new Profiles.BasicPrivilegeProfile.Constraint(x.Name, x.Value)));
                        }
                    }
                }
            }

            if (identity.HasAttribute(DKSaml20BasicPrivilegeProfileSimpleAttribute.NAME))
            {
                var simpleProfiles = identity[DKSaml20BasicPrivilegeProfileSimpleAttribute.NAME];
                foreach (var attribute in simpleProfiles)
                {
                    foreach (var attributeValue in attribute.AttributeValue)
                    {
                        yield return new Privilege(null, attributeValue);
                    }
                }
            }
        }
    }
}