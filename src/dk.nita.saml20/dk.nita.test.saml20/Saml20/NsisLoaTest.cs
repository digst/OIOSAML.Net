using System;
using System.Configuration;
using System.IO;
using System.Xml.Serialization;
using dk.nita.saml20.config;
using dk.nita.saml20.Profiles.DKSaml20.Attributes;
using dk.nita.saml20.protocol;
using NUnit.Framework;
using Saml2.Properties;

namespace dk.nita.test.Saml20
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

        [TestCase("Substantial", "Substantial")]
        [TestCase("High", "Substantial")]
        [TestCase("Low", "Low")]
        public void DemandAtOrAboveTheMinimumIsSent(string demanded, string configured)
        {
            Assert.IsNull(Saml20SignonHandler.DemandedNsisLoaError(demanded, configured));
        }

        [Test]
        public void DemandBelowTheMinimumIsRefused()
        {
            Assert.AreEqual(Resources.DemandingLevelOfAssuranceBelowMinimum, Saml20SignonHandler.DemandedNsisLoaError("Low", "Substantial"));
        }

        [TestCase("high")]
        [TestCase("Medium")]
        public void DemandThatIsNotANsisLevelIsRefused(string demanded)
        {
            Assert.AreEqual(Resources.DemandingLevelOfAssuranceError, Saml20SignonHandler.DemandedNsisLoaError(demanded, "Low"));
        }

        [TestCase(true, "3", null, true)]
        [TestCase(true, "3", "High", false)]
        [TestCase(true, null, null, false)]
        [TestCase(false, "3", null, false)]
        public void LegacyAssuranceLevelIsUsedOnlyWithoutADemandedNsisLoa(bool allowed, string assuranceLevel, string demanded, bool expected)
        {
            Assert.AreEqual(expected, Saml20SignonHandler.UsesLegacyAssuranceLevel(allowed, assuranceLevel, demanded));
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
        [TestCase(" Substantial ")]
        [TestCase(null)]
        public void UnknownMinimumNsisLoaIsRejected(string value)
        {
            Assert.Throws<ConfigurationErrorsException>(() => new SAML20FederationConfig { MinimumNsisLoa = value });
        }

        [Test]
        public void UnknownMinimumNsisLoaFailsWhenTheConfigurationIsRead()
        {
            var xml = "<SAML20Federation xmlns=\"urn:dk.nita.saml20.configuration\"><MinimumNsisLoa>substantial</MinimumNsisLoa></SAML20Federation>";

            var e = Assert.Throws<InvalidOperationException>(() => new XmlSerializer(typeof(SAML20FederationConfig)).Deserialize(new StringReader(xml)));

            Assert.IsInstanceOf<ConfigurationErrorsException>(e.InnerException);
            StringAssert.Contains("MinimumNsisLoa must be Low, Substantial or High", e.InnerException.Message);
        }

        [Test]
        public void MissingMinimumNsisLoaIsSubstantial()
        {
            var xml = "<SAML20Federation xmlns=\"urn:dk.nita.saml20.configuration\"></SAML20Federation>";

            var config = (SAML20FederationConfig)new XmlSerializer(typeof(SAML20FederationConfig)).Deserialize(new StringReader(xml));

            Assert.AreEqual("Substantial", config.MinimumNsisLoa);
        }
    }
}
