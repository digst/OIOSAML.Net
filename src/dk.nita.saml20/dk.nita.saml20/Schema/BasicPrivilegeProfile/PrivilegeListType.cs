namespace dk.nita.saml20.Schema.BasicPrivilegeProfile
{
    /// <summary>
    /// 
    /// </summary>
    [System.Serializable()]
    [System.Xml.Serialization.XmlType(Namespace = "http://itst.dk/oiosaml/basic_privilege_profile")]
    [System.Xml.Serialization.XmlRoot("PrivilegeList", Namespace = "http://itst.dk/oiosaml/basic_privilege_profile", IsNullable = false)]
    public partial class PrivilegeListType
    {
        /// <summary>
        /// 
        /// </summary>
        [System.Xml.Serialization.XmlElement("PrivilegeGroup", Form = System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public PrivilegeGroupType[] PrivilegeGroups { get; set; }
    }
}
