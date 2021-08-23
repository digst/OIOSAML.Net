using dk.nita.saml20.Utils;
using NUnit.Framework;

namespace dk.nita.test.Saml20.Utils
{
    [TestFixture]
    public class BrowserSupportUtilTest
    {
        [Test]
        public void WillNotSendSameSiteNoneToIos12()
        {
            Assert.IsFalse(BrowserSupportUtil.ShouldSendSameSiteNone("Mozilla/5.0 (iPhone; CPU iPhone OS 12_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"));
        }
    }
}