using System;
using System.Xml.Serialization;

namespace dk.nita.saml20.Schema.Protocol
{
    /// <summary>
    /// The AppSwitch contains the Xml data contract for the AppSwitch data.
    /// </summary>
    [XmlRoot("AppSwitch", Namespace = "https://data.gov.dk/eid/saml/extensions")]
    
    [Serializable]
    public class AppSwitch
    {
        /// <summary>
        /// The platform the app is running on
        /// </summary>
        public AppSwitchPlatform Platform { get; set; }

        /// <summary>
        /// The return URL for the app to return to after authentication
        /// </summary>
        public string ReturnURL { get; set; }
    }
}