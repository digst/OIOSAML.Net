using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using dk.nita.saml20;
using dk.nita.saml20.Bindings;
using dk.nita.saml20.config;
using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.Utils;
using NUnit.Framework;

namespace dk.nita.test.Saml20.Protocol
{
    /// <summary>
    /// [OIO-ALG-01] algorithms and XML hardening for received SAML messages.
    /// </summary>
    [TestFixture]
    public class AlgorithmAndXmlHardeningTest
    {
        private static readonly X509Certificate2 Certificate = new X509Certificate2(@"Saml20\Certificates\sts_dev_certificate.pfx", "test1234");

        private const string RsaSha384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
        private const string Sha384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";

        /// <summary>
        /// The test assertion, signed the way the IdP does: an enveloped signature after the Issuer, referencing the assertion's ID.
        /// </summary>
        private static XmlDocument SignedAssertion(string signatureMethod, string digestMethod, Action<SignedXml> changeSignature = null)
        {
            var doc = AssertionUtil.GetTestAssertion_01();
            var id = doc.DocumentElement.GetAttribute("ID");

            var signedXml = new SignedXml(doc) { SigningKey = Certificate.GetRSAPrivateKey() };
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = signatureMethod;
            var reference = new Reference("#" + id) { DigestMethod = digestMethod };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(reference);
            changeSignature?.Invoke(signedXml);
            signedXml.ComputeSignature();

            var issuer = doc.DocumentElement.GetElementsByTagName("Issuer", Saml20Constants.ASSERTION)[0];
            doc.DocumentElement.InsertAfter(doc.ImportNode(signedXml.GetXml(), true), issuer);
            return doc;
        }

        private static bool Verify(XmlDocument doc)
        {
            return XmlSignatureUtils.CheckSignature(doc.DocumentElement, Certificate.GetRSAPublicKey());
        }

        [TestCase(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA256Url)]
        [TestCase(RsaSha384, Sha384)]
        [TestCase(SignedXml.XmlDsigRSASHA512Url, SignedXml.XmlDsigSHA512Url)]
        public void AllowedAlgorithmsAreVerified(string signatureMethod, string digestMethod)
        {
            Assert.IsTrue(Verify(SignedAssertion(signatureMethod, digestMethod)));
        }

        [Test]
        public void RsaSha1SignatureIsRefused()
        {
            Assert.Throws<InvalidOperationException>(() => Verify(SignedAssertion(SignedXml.XmlDsigRSASHA1Url, SignedXml.XmlDsigSHA256Url)));
        }

        [Test]
        public void Sha1DigestIsRefused()
        {
            Assert.Throws<InvalidOperationException>(() => Verify(SignedAssertion(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA1Url)));
        }

        [Test]
        public void SignatureThatIsNotADirectChildIsRefused()
        {
            var doc = SignedAssertion(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA256Url);
            var signature = doc.DocumentElement.GetElementsByTagName("Signature", Saml20Constants.XMLDSIG)[0];
            var subject = doc.DocumentElement.GetElementsByTagName(Subject.ELEMENT_NAME, Saml20Constants.ASSERTION)[0];
            doc.DocumentElement.RemoveChild(signature);
            subject.AppendChild(signature);

            Assert.Throws<InvalidOperationException>(() => Verify(doc));
        }

        [Test]
        public void SignatureWithASecondReferenceIsRefused()
        {
            var doc = SignedAssertion(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA256Url, signedXml =>
            {
                var second = new Reference("#" + ((Reference)signedXml.SignedInfo.References[0]).Uri.Substring(1)) { DigestMethod = SignedXml.XmlDsigSHA256Url };
                second.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                signedXml.AddReference(second);
            });

            Assert.Throws<InvalidOperationException>(() => Verify(doc));
        }

        [Test]
        public void ReferenceToTheWholeDocumentIsRefused()
        {
            var doc = SignedAssertion(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA256Url, signedXml =>
            {
                ((Reference)signedXml.SignedInfo.References[0]).Uri = "";
            });

            Assert.Throws<InvalidOperationException>(() => Verify(doc));
        }

        [Test]
        public void TamperedAssertionIsNotVerified()
        {
            var doc = SignedAssertion(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA256Url);
            var issuer = doc.DocumentElement.GetElementsByTagName("Issuer", Saml20Constants.ASSERTION)[0];
            issuer.InnerText = "https://other.example.dk";

            Assert.IsFalse(Verify(doc));
        }

        private static string Deflate(string message)
        {
            using (var output = new MemoryStream())
            {
                using (var deflate = new DeflateStream(output, CompressionMode.Compress))
                {
                    var bytes = Encoding.UTF8.GetBytes(message);
                    deflate.Write(bytes, 0, bytes.Length);
                }
                return Convert.ToBase64String(output.ToArray());
            }
        }

        [Test]
        public void RedirectMessageWithinTheLimitIsInflated()
        {
            var message = "<samlp:LogoutRequest/>" + new string(' ', 1000);
            Assert.AreEqual(message, HttpRedirectBindingParser.DeflateDecompress(Deflate(message)));
        }

        [Test]
        public void RedirectMessageOverTheLimitIsRefused()
        {
            var message = new string('a', HttpRedirectBindingParser.MaximumInflatedMessageLength + 1);
            Assert.Throws<Saml20FormatException>(() => HttpRedirectBindingParser.DeflateDecompress(Deflate(message)));
        }

        [Test]
        public void ReceivedXmlWithADtdIsRefused()
        {
            Assert.Throws<XmlException>(() => SafeXml.Load("<!DOCTYPE Status [<!ENTITY e \"x\">]><Status>&e;</Status>"));
        }

        [Test]
        public void DeserializingXmlWithADtdIsRefused()
        {
            var xml = "<!DOCTYPE Status [<!ENTITY e \"x\">]><samlp:Status xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"><samlp:StatusMessage>&e;</samlp:StatusMessage></samlp:Status>";
            Assert.Catch(() => Serialization.DeserializeFromXmlString<dk.nita.saml20.Schema.Protocol.Status>(xml));
        }

        [Test]
        public void ReceivedXmlKeepsItsWhitespace()
        {
            Assert.IsTrue(SafeXml.Load("<a> <b/> </a>").PreserveWhitespace);
            Assert.AreEqual("<a> <b /> </a>", SafeXml.Load("<a> <b/> </a>").OuterXml);
        }

        [TestCase("SHA1")]
        [TestCase("MD5")]
        public void OutboundHashAlgorithmOtherThanSha256OrSha512IsRejected(string value)
        {
            Assert.Throws<InvalidOperationException>(() => new IDPEndPoint { ShaHashingAlgorithm = value });
            Assert.Throws<InvalidOperationException>(() => new FederationConfig { MetaDataShaHashingAlgorithm = value });
        }

        [TestCase("SHA256")]
        [TestCase("SHA512")]
        public void OutboundSha256AndSha512AreAccepted(string value)
        {
            Assert.AreEqual(value, new IDPEndPoint { ShaHashingAlgorithm = value }.ShaHashingAlgorithm);
        }

        [Test]
        public void RedirectBindingSignsWithSha256ByDefault()
        {
            Assert.AreEqual(ShaHashingAlgorithm.SHA256, new HttpRedirectBindingBuilder().ShaHashingAlgorithm);
        }
    }
}
