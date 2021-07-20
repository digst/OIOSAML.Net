namespace dk.nita.saml20.Schema.BasicPrivilegeProfile
{
    /// <summary>
    /// Representing the intermediate model of the basic privilege profile
    /// </summary>
    [System.Serializable]
    [System.Xml.Serialization.XmlType(Namespace = Constants.XmlNamespace)]
    [System.Xml.Serialization.XmlRoot("PrivilegeList", Namespace = Constants.XmlNamespace, IsNullable = false)]
    public partial class PrivilegeListType
    {
        /// <summary>
        /// The privilege groups for the profile
        /// </summary>
        [System.Xml.Serialization.XmlElement("PrivilegeGroup", Form = System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public PrivilegeGroupType[] PrivilegeGroups { get; set; }
    }
}
