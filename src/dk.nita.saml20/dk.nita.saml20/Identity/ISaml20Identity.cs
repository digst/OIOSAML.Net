using System.Collections.Generic;
using System.Security.Principal;
using dk.nita.saml20.Profiles.BasicPrivilegeProfile;
using dk.nita.saml20.Schema.Core;

namespace dk.nita.saml20.identity
{
    /// <summary>
    /// The SAML 2.0 extension to the <c>IIdentity</c> interface.
    /// </summary>
    public interface ISaml20Identity : IEnumerable<SamlAttribute>, IIdentity 
    {
        /// <summary>
        /// Retrieve an saml 20 attribute using its name. Note that this is the value contained in the 'Name' attribute, and 
        /// not the 'FriendlyName' attribute.
        /// </summary>        
        /// <exception cref="KeyNotFoundException">If the identity instance does not have the requested attribute.</exception>
        List<SamlAttribute> this[string attributeName] { get; }

        /// <summary>
        /// Check if the identity contains a certain attribute.
        /// </summary>
        /// <param name="attributeName">The name of the attribute to look for.</param>        
        bool HasAttribute(string attributeName);

        /// <summary>
        /// 
        /// </summary>
        IEnumerable<Privilege> BasicPrivilegeProfile { get; }
    }
}