using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Serialization;
using dk.nita.saml20.Schema.Protocol;

namespace dk.nita.saml20.Utils
{
    /// <summary>
    /// Serialization of AppSwitch element.
    /// </summary>
    public static class AppSwitchSerialization
    {
        /// <summary>
        /// Serializes as XmlElement.
        /// </summary>
        /// <param name="appSwitch">AppSwitch instance.</param>
        /// <param name="owner">Parent xml document.</param>
        /// <returns>Serialized Xml document.</returns>
        public static XmlElement ToXmlElement(this AppSwitch appSwitch, XmlDocument owner)
        {
            using (var memoryStream = new MemoryStream())
            {
                using (var streamWriter = new StreamWriter(memoryStream))
                {
                    var xmlSerializer = new XmlSerializer(typeof(AppSwitch));
                    xmlSerializer.Serialize(streamWriter, appSwitch);
                    var xElement = XElement.Parse(Encoding.UTF8.GetString(memoryStream.ToArray()));  
                    return (XmlElement)owner.ReadNode(xElement.CreateReader());
                }    
            }
        }
    }
}