using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Principal;
using dk.nita.saml20.Session;
using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.Identity;
using dk.nita.saml20.Utils;
using dk.nita.saml20.Profiles.BasicPrivilegeProfile;

namespace dk.nita.saml20.identity
{
    /// <summary>
    /// <para>
    /// A specialized version of GenericIdentity that contains attributes from a SAML 2 assertion. 
    /// </para>
    /// <para>
    /// The AuthenticationType property of the Identity will be "urn:oasis:names:tc:SAML:2.0:assertion".
    /// </para>
    /// <para>
    /// The order of the attributes is not maintained when converting from the saml assertion to this class. 
    /// </para>
    /// </summary>
    [Serializable]
    public class Saml20Identity : GenericIdentity, ISaml20Identity
    {
        private readonly Dictionary<string, List<SamlAttribute>> _attributes;

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20Identity"/> class.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <param name="attributes">The attributes.</param>
        public Saml20Identity(string name, ICollection<SamlAttribute> attributes)
            : base(name, Saml20Constants.ASSERTION)
        {
            _attributes = new Dictionary<string, List<SamlAttribute>>();

            foreach (SamlAttribute att in attributes)
            {
                if (!_attributes.ContainsKey(att.Name))
                    _attributes.Add(att.Name, new List<SamlAttribute>());
                _attributes[att.Name].Add(att);
            }
        }

        /// <summary>
        /// <para>
        /// Retrieves the user's identity and the attributes that were extracted from the saml assertion.
        /// </para>
        /// <para>
        /// This property may return null if the initialization of the saml identity fails.
        /// </para>
        /// </summary>
        public static Saml20Identity Current
        {
            get
            {
                if (Saml20PrincipalCache.GetPrincipal() != null)
                    return Saml20PrincipalCache.GetPrincipal().Identity as Saml20Identity;
                return null;
            }
        }

        /// <summary>
        /// Checks if an OIOSAML session exists.
        /// </summary>
        public static bool IsInitialized()
        {
            return SessionStore.DoesSessionExists();
        }

        /// <summary>
        /// This method converts the received Saml assertion into a .Net principal.
        /// </summary>
        internal static IPrincipal InitSaml20Identity(Saml20AssertionLite assertion)
        {
            string subjectIdentifier = assertion.Subject.Value;

            // Create identity
            var identity = new Saml20Identity(subjectIdentifier, assertion.Attributes);

            return new GenericPrincipal(identity, new string[] { });
        }

        /// <summary>
        /// Retrieve an saml 20 attribute using its name. Note that this is the value contained in the 'Name' attribute, and 
        /// not the 'FriendlyName' attribute.
        /// </summary>        
        /// <exception cref="KeyNotFoundException">If the identity instance does not have the requested attribute.</exception>
        public List<SamlAttribute> this[string attributeName]
        {
            get { return _attributes[attributeName]; }
        }

        /// <summary>
        /// Check if the identity contains a certain attribute.
        /// </summary>
        /// <param name="attributeName">The name of the attribute to look for.</param>        
        public bool HasAttribute(string attributeName)
        {
            return _attributes.ContainsKey(attributeName);
        }

        /// <summary>
        /// 
        /// </summary>
        public IEnumerable<Privilege> BasicPrivilegeProfile
        {
            get
            {
                return Saml20Utils.GetBasicPrivilegeProfilePrivileges(this);
            }
        }

        internal void AddAttributeFromQuery(string name, SamlAttribute value)
        {

            if (!_attributes.ContainsKey(name))
                _attributes.Add(name, new List<SamlAttribute>());
            if (!_attributes[name].Contains(value))
                _attributes[name].Add(value);

        }

        #region IEnumerable<Attribute> Members

        /// <summary>
        /// Returns an enumerator that iterates through the collection.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.Collections.Generic.IEnumerator`1"/> that can be used to iterate through the collection.
        /// </returns>
        IEnumerator<SamlAttribute> IEnumerable<SamlAttribute>.GetEnumerator()
        {
            List<SamlAttribute> allAttributes = new List<SamlAttribute>();
            foreach (string name in _attributes.Keys)
            { allAttributes.AddRange(_attributes[name]); };
            return allAttributes.GetEnumerator();
        }

        #endregion

        #region IEnumerable Members

        /// <summary>
        /// Returns an enumerator that iterates through a collection.
        /// </summary>
        /// <returns>
        /// An <see cref="T:System.Collections.IEnumerator"/> object that can be used to iterate through the collection.
        /// </returns>
        public IEnumerator GetEnumerator()
        {
            return ((IEnumerable<SamlAttribute>)this).GetEnumerator();
        }

        #endregion
    }
}
