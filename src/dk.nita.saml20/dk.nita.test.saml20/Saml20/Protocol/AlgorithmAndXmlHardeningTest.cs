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

        private static bool Refused(XmlDocument doc)
        {
            try
            {
                return !Verify(doc);
            }
            catch (Exception e) when (e is InvalidOperationException || e is CryptographicException)
            {
                return true;
            }
        }

        [Test]
        public void RsaSha256WithSha256IsVerified()
        {
            Assert.IsTrue(Verify(SignedAssertion(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA256Url)));
        }

        [TestCase(RsaSha384, SignedXml.XmlDsigSHA256Url)]
        [TestCase(SignedXml.XmlDsigRSASHA512Url, SignedXml.XmlDsigSHA256Url)]
        [TestCase(SignedXml.XmlDsigRSASHA256Url, Sha384)]
        [TestCase(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA512Url)]
        public void AlgorithmsOutsideOioAlg01AreRefused(string signatureMethod, string digestMethod)
        {
            Assert.Throws<InvalidOperationException>(() => Verify(SignedAssertion(signatureMethod, digestMethod)));
        }

        [Test]
        public void InclusiveCanonicalizationIsRefused()
        {
            var doc = SignedAssertion(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA256Url, signedXml =>
            {
                signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigC14NTransformUrl;
            });

            Assert.Throws<InvalidOperationException>(() => Verify(doc));
        }

        [Test]
        public void TransformOtherThanEnvelopedAndExclusiveCanonicalizationIsRefused()
        {
            var doc = SignedAssertion(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA256Url, signedXml =>
            {
                ((Reference)signedXml.SignedInfo.References[0]).AddTransform(new XmlDsigC14NWithCommentsTransform());
            });

            Assert.Throws<InvalidOperationException>(() => Verify(doc));
        }

        [Test]
        public void SignatureWithoutTheEnvelopedTransformIsRefused()
        {
            var doc = SignedAssertion(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA256Url, signedXml =>
            {
                var reference = (Reference)signedXml.SignedInfo.References[0];
                var withoutEnveloped = new Reference(reference.Uri) { DigestMethod = reference.DigestMethod };
                withoutEnveloped.AddTransform(new XmlDsigExcC14NTransform());
                signedXml.SignedInfo.References.Clear();
                signedXml.AddReference(withoutEnveloped);
            });

            Assert.Throws<InvalidOperationException>(() => Verify(doc));
        }

        [Test]
        public void SecondElementWithTheSignedIdIsRefused()
        {
            var doc = SignedAssertion(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA256Url);
            var copy = (XmlElement)doc.DocumentElement.CloneNode(true);
            copy.RemoveChild(copy.GetElementsByTagName("Signature", Saml20Constants.XMLDSIG)[0]);
            doc.DocumentElement.GetElementsByTagName(Subject.ELEMENT_NAME, Saml20Constants.ASSERTION)[0].AppendChild(copy);

            Assert.IsTrue(Refused(doc));
        }

        [Test]
        public void SignatureCopiedToOtherContentWithTheSameIdIsRefused()
        {
            var signed = SignedAssertion(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA256Url);
            var other = AssertionUtil.GetTestAssertion_01();
            other.DocumentElement.GetElementsByTagName("Issuer", Saml20Constants.ASSERTION)[0].InnerText = "https://other.example.dk";
            var signature = signed.DocumentElement.GetElementsByTagName("Signature", Saml20Constants.XMLDSIG)[0];
            var issuer = other.DocumentElement.GetElementsByTagName("Issuer", Saml20Constants.ASSERTION)[0];
            other.DocumentElement.InsertAfter(other.ImportNode(signature, true), issuer);

            Assert.IsTrue(Refused(other));
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
        [TestCase("SHA512")]
        [TestCase("MD5")]
        public void OutboundHashAlgorithmOtherThanSha256IsRejected(string value)
        {
            Assert.Throws<InvalidOperationException>(() => new IDPEndPoint { ShaHashingAlgorithm = value });
            Assert.Throws<InvalidOperationException>(() => new FederationConfig { MetaDataShaHashingAlgorithm = value });
        }

        [Test]
        public void OutboundSha256IsAccepted()
        {
            Assert.AreEqual("SHA256", new IDPEndPoint { ShaHashingAlgorithm = "SHA256" }.ShaHashingAlgorithm);
        }

        [Test]
        public void MetadataFileWithADtdIsNotRead()
        {
            using (var stream = new MemoryStream(Encoding.UTF8.GetBytes("<!DOCTYPE EntityDescriptor [<!ENTITY e \"x\">]><EntityDescriptor>&e;</EntityDescriptor>")))
            {
                Assert.Throws<XmlException>(() => SafeXml.Load(stream));
            }
        }

        [Test]
        public void RedirectBindingSignsWithSha256ByDefault()
        {
            Assert.AreEqual(ShaHashingAlgorithm.SHA256, new HttpRedirectBindingBuilder().ShaHashingAlgorithm);
        }
    }
}
