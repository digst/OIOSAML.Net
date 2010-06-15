using System.Xml.Serialization;
using dk.nita.saml2.ext.brs;

/// <summary>
/// Strongly typed representation of the Privilege element
/// </summary>
[XmlType(Namespace = BRSConstants.XML_NAMESPACE)]
public class PrivilegeType {
    
    private string _valueField;

    /// <summary>
    /// Gets or sets the value.
    /// </summary>
    /// <value>The value.</value>
    [XmlText()]
    public string Value {
        get {
            return _valueField;
        }
        set {
            _valueField = value;
        }
    }
}