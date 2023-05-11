using System.Linq;
using System.Xml;
using dk.nita.saml20.Schema.Protocol;
using dk.nita.saml20.Utils;
using NUnit.Framework;

namespace dk.nita.test.Saml20
{
    [TestFixture]
    public class SamlAuthnRequestTest
    {
        [Test]
        public void AuthnRequestShallDeserializeWithAppSwitch()
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.Load(@"Saml20\Protocol\AuthnRequests\WithValidAppSwitch.xml");
            AuthnRequest req = Serialization.DeserializeFromXmlString<AuthnRequest>(doc.InnerXml);
            Assert.IsNotNull(req.Extensions);
            Assert.IsNotNull(req.Extensions.Any);
            Assert.AreEqual(1, req.Extensions.Any.Length);
        }
        
        [Test]
        public void AppSwitchElementShallDeserialize()
        {
            
            var s = @"<nl:AppSwitch xmlns:nl=""https://data.gov.dk/eid/saml/extensions""><nl:Platform>iOS</nl:Platform><nl:ReturnURL>https://sp3.dev-nemlog-in.dk</nl:ReturnURL></nl:AppSwitch>";
            var appSwitch = Serialization.DeserializeFromXmlString<AppSwitch>(s);
            Assert.AreEqual("iOS", appSwitch.Platform.ToString());
            Assert.AreEqual("https://sp3.dev-nemlog-in.dk", appSwitch.ReturnURL);
        }
    }
}