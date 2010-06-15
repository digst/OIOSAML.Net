using dk.nita.saml20.Schema.Core;

namespace dk.nita.saml20.Profiles.DKSaml20.Attributes
{
    /// <summary>
    /// 
    /// </summary>
    public class DKSaml20PidNumberAttribute : DKSaml20Attribute
    {
        /// <summary>
        /// Attribute name
        /// </summary>
        public const string NAME = "dk:gov:saml:attribute:PidNumberIdentifier";

        /// <summary>
        /// Creates an attribute with the specified value.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        public static SamlAttribute Create(string value)
        {
            return Create(NAME, null, value);
        }
    }
}