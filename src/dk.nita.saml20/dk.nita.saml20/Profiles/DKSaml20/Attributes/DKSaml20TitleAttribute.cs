using dk.nita.saml20.Schema.Core;

namespace dk.nita.saml20.Profiles.DKSaml20.Attributes
{
    /// <summary>
    /// 
    /// </summary>
    public class DKSaml20TitleAttribute : DKSaml20Attribute
    {
        /// <summary>
        /// Attribute name
        /// </summary>
        public const string NAME = "urn:oid:2.5.4.12";
        /// <summary>
        /// Friendly name
        /// </summary>
        public const string FRIENDLYNAME = "title";

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