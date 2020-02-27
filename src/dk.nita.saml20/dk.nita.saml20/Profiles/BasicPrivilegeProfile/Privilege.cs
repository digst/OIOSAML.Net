namespace dk.nita.saml20.Profiles.BasicPrivilegeProfile
{
    /// <summary>
    /// 
    /// </summary>
    public class Privilege
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="scope"></param>
        /// <param name="value"></param>
        public Privilege(string scope, string value)
        {
            Scope = string.IsNullOrWhiteSpace(scope) ? null : scope;
            Value = value;
        }
        /// <summary>
        /// 
        /// </summary>
        public string Value { get; private set; }

        /// <summary>
        /// 
        /// </summary>
        public string Scope { get; private set; }
    }
}
