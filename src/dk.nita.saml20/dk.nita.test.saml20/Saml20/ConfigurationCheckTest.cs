using System.Configuration;
using System.Security.Cryptography.Xml;
using dk.nita.saml20.config;
using dk.nita.saml20.Utils;
using NUnit.Framework;

namespace dk.nita.test.Saml20
{
    [TestFixture]
    public class ConfigurationCheckTest
    {
        [Test]
        public void OmittingTheAssertionSignatureCheckIsRefused()
        {
            Assert.Throws<ConfigurationErrorsException>(() => new IDPEndPoint { OmitAssertionSignatureCheck = true });
            Assert.IsFalse(new IDPEndPoint { OmitAssertionSignatureCheck = false }.OmitAssertionSignatureCheck);
        }

        [TestCase("dk.nita.saml20.Specification.DefaultCertifcateSpecification, dk.nita.saml20")]
        [TestCase("System.String")]
        [TestCase("")]
        public void CertificateValidationTypeThatCantBeUsedIsRefused(string type)
        {
            Assert.Throws<ConfigurationErrorsException>(() => new CertificateValidationElement { type = type });
        }

        [Test]
        public void CertificateValidationTypeIsAccepted()
        {
            const string type = "dk.nita.saml20.Specification.DefaultCertificateSpecification, dk.nita.saml20";
            Assert.AreEqual(type, new CertificateValidationElement { type = type }.type);
        }

        [Test]
        public void X509DataWithoutACertificateGivesNoCertificate()
        {
            var x509Data = new KeyInfoX509Data();
            x509Data.AddSubjectName("CN=test");
            Assert.IsNull(XmlSignatureUtils.GetCertificateFromKeyInfo(x509Data));
        }
    }
}
