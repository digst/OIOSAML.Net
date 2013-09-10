using System.Xml.Serialization;
using System.Collections.Generic;

namespace dk.nita.saml2.ext.brs.schema
{

    [XmlType(Namespace = BRSConstants.XML_NAMESPACE)]
    [XmlRoot("Authorisation", Namespace = BRSConstants.XML_NAMESPACE, IsNullable = false)]
    public class AuthorisationType {

        public AuthorisationType()
        {
            _privilegeField = new List<PrivilegeType>();
        }

        private List<PrivilegeType> _privilegeField;
    
        private string _resourceField;
    
        [XmlElement("Privilege")]
        public List<PrivilegeType> Privilege {
            get {
                return _privilegeField;
            }
            set {
                _privilegeField = value;
            }
        }
    
        [XmlAttribute(DataType="anyURI")]
        public string resource {
            get {
                return _resourceField;
            }
            set {
                _resourceField = value;
            }
        }
    }
}