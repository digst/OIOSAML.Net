using System.Xml.Serialization;

namespace dk.nita.saml20.config
{
    /// <summary>
    /// Configuration element for app switch return url.
    /// </summary>
    public class AppSwitchReturnURL 
    {
        /// <summary>
        /// AppSwitch platform. Can be either Android or iOS.
        /// </summary>
        [XmlAttribute(AttributeName = "platform")]
        public string Platform;

        /// <summary>
        /// Value of the return URL.
        /// </summary>
        [XmlText]
        public string Value;
    }
}