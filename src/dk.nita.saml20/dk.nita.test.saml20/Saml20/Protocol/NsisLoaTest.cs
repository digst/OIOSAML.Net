using System.Configuration;
using dk.nita.saml20.config;
using dk.nita.saml20.Profiles.DKSaml20.Attributes;
using NUnit.Framework;

namespace dk.nita.test.Saml20.Protocol
{
    [TestFixture]
    public class NsisLoaTest
    {
        [TestCase("Low", "Low", true)]
        [TestCase("Substantial", "Low", true)]
        [TestCase("High", "Substantial", true)]
        [TestCase("Low", "Substantial", false)]
        [TestCase("Substantial", "High", false)]
        [TestCase("substantial", "Low", false)]
        [TestCase("Unknown", "Low", false)]
        [TestCase(null, "Low", false)]
        [TestCase("High", "Unknown", false)]
        public void IsAtLeast(string level, string minimum, bool expected)
        {
            Assert.AreEqual(expected, DKSaml20NsisLoaAttribute.IsAtLeast(level, minimum));
        }

        [TestCase("Substantial", null, "Substantial")]
        [TestCase("Substantial", "Low", "Substantial")]
        [TestCase("Substantial", "High", "High")]
        [TestCase("Low", "Substantial", "Substantial")]
        [TestCase("High", "Unknown", "High")]
        public void DemandedLoaCanOnlyRaiseTheConfiguredMinimum(string configured, string demanded, string expected)
        {
            Assert.AreEqual(expected, DKSaml20NsisLoaAttribute.Stricter(configured, demanded));
        }

        [TestCase("Low")]
        [TestCase("Substantial")]
        [TestCase("High")]
        public void ValidMinimumNsisLoaIsAccepted(string value)
        {
            var config = new SAML20FederationConfig { MinimumNsisLoa = value };
            Assert.AreEqual(value, config.MinimumNsisLoa);
        }

        [TestCase("substantial")]
        [TestCase("Medium")]
        [TestCase("")]
        [TestCase(null)]
        public void UnknownMinimumNsisLoaIsRejected(string value)
        {
            Assert.Throws<ConfigurationErrorsException>(() => new SAML20FederationConfig { MinimumNsisLoa = value });
        }
    }
}
