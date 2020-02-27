namespace dk.nita.saml20.Schema.BasicPrivilegeProfile
{
    /// <summary>
    /// 
    /// </summary>
    [System.Serializable()]
    [System.Xml.Serialization.XmlType(Namespace = "http://itst.dk/oiosaml/basic_privilege_profile")]
    public partial class PrivilegeGroupType
    {
        /// <summary>
        /// 
        /// </summary>
        [System.Xml.Serialization.XmlElement("Privilege", Form = System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public string[] Privilege { get; set; }

        /// <summary>
        /// 
        /// </summary>
        [System.Xml.Serialization.XmlAttribute()]
        public string Scope { get; set; }
    }
}
