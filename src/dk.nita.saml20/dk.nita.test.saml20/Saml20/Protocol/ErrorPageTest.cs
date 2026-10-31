using dk.nita.saml20.protocol.pages;
using NUnit.Framework;

namespace dk.nita.test.Saml20.Protocol
{
    [TestFixture]
    public class ErrorPageTest
    {
        [Test]
        public void ErrorTextIsEncoded()
        {
            Assert.AreEqual("Issuer &lt;b&gt;&quot;x&quot; &amp; y&lt;/b&gt;", ErrorPage.ToHtml("Issuer <b>\"x\" & y</b>"));
        }

        [Test]
        public void LineBreaksAreKept()
        {
            Assert.AreEqual("first<br />second<br />third", ErrorPage.ToHtml("first\r\nsecond\nthird"));
        }

        [Test]
        public void MissingTextIsEmpty()
        {
            Assert.AreEqual(string.Empty, ErrorPage.ToHtml(null));
        }
    }
}
