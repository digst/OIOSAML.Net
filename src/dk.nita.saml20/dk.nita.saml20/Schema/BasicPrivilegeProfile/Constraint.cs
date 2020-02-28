namespace dk.nita.saml20.Schema.BasicPrivilegeProfile
{
    /// <summary>
    /// Constraints are essentially key/value pairs where the key identifies the constraint and the value
    /// specifies the restriction and they are always applied to a User-Privilege relation (assignment)
    /// </summary>
    [System.Serializable()]
    [System.Xml.Serialization.XmlType(Namespace = "http://itst.dk/oiosaml/basic_privilege_profile")]
    public partial class Constraint
    {
        /// <summary>
        /// The name/key of the constraints
        /// </summary>
        [System.Xml.Serialization.XmlAttribute()]
        public string Name { get; set; }

        /// <summary>
        /// The restriction/value of the constraint
        /// </summary>
        [System.Xml.Serialization.XmlTextAttribute()]
        public string Value { get; set; }
    }
}
