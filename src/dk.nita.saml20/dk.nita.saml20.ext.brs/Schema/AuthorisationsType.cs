using System.Xml.Serialization;
using System.Collections.Generic;

namespace dk.nita.saml2.ext.brs.schema
{
    /// <summary>
    /// Strongly types representation of the Authorisations element
    /// </summary>
    [XmlType(Namespace = BRSConstants.XML_NAMESPACE)]
    [XmlRoot("Authorisations", Namespace = BRSConstants.XML_NAMESPACE, IsNullable = false)]
    public class AuthorisationsType {

        public AuthorisationsType()
        {
            _authorisationsField = new List<AuthorisationType>();
        }

        private List<AuthorisationType> _authorisationsField;

        /// <summary>
        /// Gets or sets the authorisations.
        /// </summary>
        /// <value>The authorisations.</value>
        [XmlElement("Authorisation", IsNullable=false)]
        public List<AuthorisationType> Authorisations {
            get {
                return _authorisationsField;
            }
            set {
                _authorisationsField = value;
            }
        }
    }
}