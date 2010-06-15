using System.Xml.Serialization;

namespace dk.nita.saml2.ext.brs.schema
{
    [XmlTypeAttribute(Namespace=BRSConstants.XML_NAMESPACE)]
    [XmlRoot("Attribute", Namespace = BRSConstants.XML_NAMESPACE, IsNullable = false)]
    public class AttributeType {
    
        private string nameField;
    
        private string nameFormatField;
    
        private string friendlyNameField;
    
        [XmlAttributeAttribute()]
        public string Name {
            get {
                return nameField;
            }
            set {
                nameField = value;
            }
        }
    
        [XmlAttributeAttribute(DataType="anyURI")]
        public string NameFormat {
            get {
                return nameFormatField;
            }
            set {
                nameFormatField = value;
            }
        }
    
        [XmlAttributeAttribute()]
        public string FriendlyName {
            get {
                return friendlyNameField;
            }
            set {
                friendlyNameField = value;
            }
        }
    }
}