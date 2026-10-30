using System;
using dk.nita.saml20.Logging;
using NUnit.Framework;

namespace dk.nita.test.Saml20
{
    [TestFixture]
    public class AuditLoggingTest
    {
        private const string Response =
            "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
            "ID=\"_response\" InResponseTo=\"_request\" IssueInstant=\"2026-10-30T12:00:00Z\" Version=\"2.0\">" +
            "<saml:Issuer> https://idp.example.dk </saml:Issuer>" +
            "<saml:Assertion ID=\"_assertion\"><saml:Subject><saml:NameID>secret-subject</saml:NameID></saml:Subject>" +
            "<saml:AttributeStatement><saml:Attribute Name=\"cpr\"><saml:AttributeValue>0101010101</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>" +
            "</saml:Assertion></samlp:Response>";

        [Test]
        public void MessageIsDescribedWithoutItsContent()
        {
            var description = AuditLogging.Describe(Response);

            Assert.AreEqual("Response ID=_response InResponseTo=_request IssueInstant=2026-10-30T12:00:00Z Issuer=https://idp.example.dk", description);
            StringAssert.DoesNotContain("secret-subject", description);
            StringAssert.DoesNotContain("0101010101", description);
        }

        [Test]
        public void UnreadableMessageIsNotLogged()
        {
            Assert.AreEqual("<unreadable message>", AuditLogging.Describe("not xml 0101010101"));
            Assert.AreEqual("<no message>", AuditLogging.Describe((System.Xml.XmlElement)null));
        }

        [Test]
        public void LineBreaksInLoggedValuesAreEscaped()
        {
            Assert.AreEqual("a\\r\\nb\\nc", AuditLogging.OneLine("a\r\nb\nc"));
            StringAssert.DoesNotContain("\n", AuditLogging.Describe(Response.Replace("idp.example.dk", "idp.example.dk\nsecond line")));
        }

        [Test]
        public void SessionIdIsLoggedAsAHash()
        {
            var sessionId = Guid.NewGuid();
            var hash = AuditLogging.HashSessionId(sessionId);

            Assert.AreEqual(16, hash.Length);
            Assert.AreEqual(hash, AuditLogging.HashSessionId(sessionId));
            Assert.AreNotEqual(hash, AuditLogging.HashSessionId(Guid.NewGuid()));
            StringAssert.DoesNotContain(sessionId.ToString("N").Substring(0, 8), hash);
        }
    }
}
