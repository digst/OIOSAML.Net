namespace dk.nita.saml20.Schema.BasicPrivilegeProfile
{
    /// <summary>
    /// Representing the PrivilegeGroup in the intermediate model of the basic privilege profile
    /// </summary>
    [System.Serializable()]
    [System.Xml.Serialization.XmlType(Namespace = "http://itst.dk/oiosaml/basic_privilege_profile")]
    public partial class PrivilegeGroupType
    {
        /// <summary>
        /// Privilege URIs are normally defined by the application or service that receives a SAML assertion issued by
        /// an Identity Provider or Security Token Service.
        /// </summary>
        [System.Xml.Serialization.XmlElement("Privilege", Form = System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public string[] Privilege { get; set; }

        /// <summary>
        /// Constraints for the group
        /// </summary>
        [System.Xml.Serialization.XmlElement("Constraint", Form = System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public Constraint[] Constraint { get; set; }

        /// <summary>
        /// Scope for the group
        /// </summary>
        [System.Xml.Serialization.XmlAttribute()]
        public string Scope { get; set; }
    }
}
