using dk.nita.saml20.config;
using NUnit.Framework;

namespace dk.nita.test.Saml20.Protocol
{
    [TestFixture]
    public class AppSwitchConfigurationTest
    {
        [Test]
        public void AppSwitchSectionShallBeReadFromConfig()
        {
            var config = SAML20FederationConfig.GetConfig();
            Assert.NotNull(config.AppSwitchReturnURL);
            Assert.AreEqual(2, config.AppSwitchReturnURL.Count);
            Assert.AreEqual(@"sp0.test-nemlog-in.dk", config.FindAppSwitchReturnUrlForPlatform("Android"));
            Assert.AreEqual(@"sp1.test-nemlog-in.dk", config.FindAppSwitchReturnUrlForPlatform("iOS"));
        }
    }
}