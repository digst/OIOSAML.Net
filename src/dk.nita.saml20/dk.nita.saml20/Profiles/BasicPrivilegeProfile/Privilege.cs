using System.Collections.Generic;
using System.Linq;

namespace dk.nita.saml20.Profiles.BasicPrivilegeProfile
{
    /// <summary>
    /// Basic Privilege profile privilege
    /// </summary>
    public class Privilege
    {
        /// <summary>
        /// Constructs a Basic privilege profile privilege without constraints
        /// </summary>
        /// <param name="scope"></param>
        /// <param name="value"></param>
        public Privilege(string scope, string value)
        {
            Scope = string.IsNullOrWhiteSpace(scope) ? null : scope;
            Value = value;
        }

        /// <summary>
        /// Constructs a Basic privilege profile privilege
        /// </summary>
        /// <param name="scope"></param>
        /// <param name="value"></param>
        /// <param name="constraints"></param>
        public Privilege(string scope, string value, IEnumerable<Constraint> constraints)
        {
            Scope = string.IsNullOrWhiteSpace(scope) ? null : scope;
            Value = value;
            Constraints = constraints.ToArray();
        }

        /// <summary>
        /// The value of the privilege
        /// </summary>
        public string Value { get; private set; }

        /// <summary>
        /// The scope for the privilege
        /// </summary>
        public string Scope { get; private set; }

        /// <summary>
        /// The constraints for the privileges 
        /// </summary>
        public Constraint[] Constraints { get; private set; }
    }
}
