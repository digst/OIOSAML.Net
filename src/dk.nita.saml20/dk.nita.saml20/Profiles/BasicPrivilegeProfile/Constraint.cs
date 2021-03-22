namespace dk.nita.saml20.Profiles.BasicPrivilegeProfile
{
    /// <summary>
    /// Constraints are essentially key/value pairs where the key identifies the constraint and the value
    /// specifies the restriction and they are always applied to a User-Privilege relation (assignment)
    /// </summary>
    public class Constraint
    {
        /// <summary>
        /// Constructs the constraint
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        public Constraint(string name, string value)
        {
            Name = name;
            Value = value;
        }

        /// <summary>
        /// The name/key of the constraints
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// The restriction/value of the constraint
        /// </summary>
        public string Value { get; private set; }
    }
}
