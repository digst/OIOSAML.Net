using System;
using dk.nita.saml20.Schema.Core;

namespace dk.nita.saml20.Profiles.DKSaml20.Attributes
{
    /// <summary>
    /// 
    /// </summary>
    public class DKSaml20NsisLoaAttribute : DKSaml20Attribute
    {
        /// <summary>
        /// Attribute name
        /// </summary>
        public const string NAME = "https://data.gov.dk/concept/core/nsis/loa";

        /// <summary>
        /// Creates an attribute with the specified value.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns></returns>
        public static SamlAttribute Create(string value)
        {
            return Create(NAME, null, value);
        }

        private static readonly string[] Levels = { "Low", "Substantial", "High" };

        /// <summary>
        /// Whether the value is one of the NSIS levels of assurance: Low, Substantial or High.
        /// </summary>
        internal static bool IsValidLevel(string level) => Rank(level) >= 0;

        /// <summary>
        /// Whether a level of assurance meets a minimum. An unknown level or minimum never does.
        /// </summary>
        internal static bool IsAtLeast(string level, string minimum)
        {
            var minimumRank = Rank(minimum);
            return minimumRank >= 0 && Rank(level) >= minimumRank;
        }

        /// <summary>
        /// The stricter of two levels of assurance. A missing or unknown value never wins.
        /// </summary>
        internal static string Stricter(string level, string other) => Rank(other) > Rank(level) ? other : level;

        private static int Rank(string level) => Array.IndexOf(Levels, level);
    }
}