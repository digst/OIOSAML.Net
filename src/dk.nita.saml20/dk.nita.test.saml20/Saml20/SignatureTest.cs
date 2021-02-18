using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using NUnit.Framework;
using dk.nita.saml20;
using dk.nita.saml20.Utils;
using Signature = dk.nita.saml20.Schema.XmlDSig.Signature;

namespace dk.nita.test.Saml20
{
    /// <summary>
    /// Contains tests that verify the signatures of the sample assertions in the Assertions directory. 
    /// 
    /// One tests performs a "bare-bone" verification, while another verifies using the <code>Assertion</code> class.
    /// </summary>
    [TestFixture]
    public class SignatureTest
    {
        /// <summary>
        /// Verifies the signature in the "Saml2Assertion_01" file. The assertion in the file is valid.
        /// </summary>
        [Test]
        public void VerifyValidSignatures()
        {
            Assert.That(VerifySignature(@"Saml20\Assertions\Saml2Assertion_01"));
            Assert.That(VerifySignature(@"Saml20\Assertions\Saml2Assertion_02"));
            Assert.That(VerifySignature(@"Saml20\Assertions\Saml2Assertion_03"));
        }

        /// <summary>
        /// Verifies that SignedXml will detect assertions that have been tampered with.
        /// </summary>
        [Test]
        public void VerifyManipulatedSignature()
        {
            Assert.IsFalse(VerifySignature(@"Saml20\Assertions\EvilSaml2Assertion_01"));
            Assert.IsFalse(VerifySignature(@"Saml20\Assertions\EvilSaml2Assertion_02"));
            Assert.IsFalse(VerifySignature(@"Saml20\Assertions\EvilSaml2Assertion_03"));
        }

        /// <summary>
        /// Deserializes the test tokens using the Safewhere DK-SAML class.
        /// </summary>
        [Ignore("test data needs fixing")]    // TODO: test data needs fixing
        public void TestDKSaml20TokenVerification_01()
        {
            AssertionUtil.DeserializeToken(@"Saml20\Assertions\Saml2Assertion_01");
            AssertionUtil.DeserializeToken(@"Saml20\Assertions\Saml2Assertion_02");
            AssertionUtil.DeserializeToken(@"Saml20\Assertions\Saml2Assertion_03");
        }

        /// <summary>
        /// Attempts to deserialize an invalid Saml-token. Tests that the Assertion class immediately "explodes".
        /// </summary>
        [Test]
        public void TestDKSaml20TokenVerification_02()
        {
            Assert.Throws<Saml20Exception>(
                () => AssertionUtil.DeserializeToken(@"Saml20\Assertions\EvilSaml2Assertion_01"),
                "Signature could not be verified.");
        }

        /// <summary>
        /// Attempts to deserialize an invalid Saml-token. Tests that the Assertion class immediately "explodes".
        /// </summary>
        [Test]
        public void TestDKSaml20TokenVerification_03()
        {
            Assert.Throws<Saml20Exception>(
                () => AssertionUtil.DeserializeToken(@"Saml20\Assertions\EvilSaml2Assertion_02"),
                "Signature could not be verified.");
        }

        /// <summary>
        /// Attempts to deserialize an invalid Saml-token. Tests that the Assertion class immediately "explodes".
        /// </summary>
        [Test]
        public void TestDKSaml20TokenVerification_04()
        {
            Assert.Throws<Saml20Exception>(
                () => AssertionUtil.DeserializeToken(@"Saml20\Assertions\EvilSaml2Assertion_03"),
                "Signature could not be verified.");
        }

        /// <summary>
        /// Tests the signing and verification of an assertion.
        /// </summary>
        [Test]
        public void TestSigning_01()
        {
            XmlDocument token = AssertionUtil.GetTestAssertion_01();
            SignDocument(token);
            bool verified = VerifySignature(token);
            Assert.That(verified);

            WriteToFile(@"signedassertion.xml", token.DocumentElement);
        }

        /// <summary>
        /// Writes the given XmlDocument to a file. 
        /// </summary>
        public static void WriteToFile(string file, XmlElement el)
        {
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Encoding = System.Text.Encoding.UTF8;
            settings.CloseOutput = true;
            XmlWriter writer = XmlWriter.Create(File.Open(file, FileMode.Create), settings);
            el.OwnerDocument.WriteContentTo(writer);
            writer.Close();
        }

        /// <summary>
        /// Tests that the manipulation of an assertion is detected by the signature.
        /// </summary>
        [Test]
        public void TestSigning_02()
        {
            XmlDocument token = AssertionUtil.GetTestAssertion_01();
            SignDocument(token);

            // Manipulate the #%!;er: Attempt to remove the <AudienceRestriction> from the list of conditions.
            XmlElement conditions =
                (XmlElement)token.GetElementsByTagName("Conditions", "urn:oasis:names:tc:SAML:2.0:assertion")[0];
            XmlElement audienceRestriction =
                (XmlElement)conditions.GetElementsByTagName("AudienceRestriction", "urn:oasis:names:tc:SAML:2.0:assertion")[0];

            conditions.RemoveChild(audienceRestriction);

            bool verified = VerifySignature(token);
            Assert.IsFalse(verified);
        }

        /// <summary>
        /// Test that the Assertion class verifies the signature of an assertion by default.
        /// </summary>
        [Test]
        public void TestSigning_04()
        {
            // Any key-containing algorithm will do - the basic assertion is NOT signed anyway
            X509Certificate2 cert = new X509Certificate2(@"Saml20\Certificates\sts_dev_certificate.pfx", "test1234");


            Assert.Throws<InvalidOperationException>(
                () =>
                {
                    new Saml20Assertion(AssertionUtil.GetTestAssertion_01().DocumentElement,
                        new AsymmetricAlgorithm[] { cert.PublicKey.Key }, false);
                },
                "Document does not contain a signature to verify.");

        }

        [Test]
        public void TestSHA256Signature()
        {
            var xmlDocument = new XmlDocument { PreserveWhitespace = true };
            xmlDocument.Load(@"Saml20\Assertions\SHA256Signedtest.xml");
            Assert.IsTrue(XmlSignatureUtils.CheckSignature(xmlDocument));
        }

        /// <summary>
        /// Signs the document given as an argument.
        /// </summary>
        private static void SignDocument(XmlDocument doc)
        {
            SignedXml signedXml = new SignedXml(doc);
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            // TODO Dynamically dig out the correct ID attribute from the XmlDocument.
            Reference reference = new Reference("#_b8977dc86cda41493fba68b32ae9291d");
            // Assert.That(reference.Uri == string.Empty);

            XmlDsigEnvelopedSignatureTransform envelope = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(envelope);

            // NOTE: C14n may require the following list of namespace prefixes. Seems to work without it, though.
            //List<string> prefixes = new List<string>();
            //prefixes.Add(doc.DocumentElement.GetPrefixOfNamespace("http://www.w3.org/2000/09/xmldsig#"));
            //prefixes.Add(doc.DocumentElement.GetPrefixOfNamespace("http://www.w3.org/2001/XMLSchema-instance"));
            //prefixes.Add(doc.DocumentElement.GetPrefixOfNamespace("http://www.w3.org/2001/XMLSchema"));
            //prefixes.Add(doc.DocumentElement.GetPrefixOfNamespace("urn:oasis:names:tc:SAML:2.0:assertion"));

            //XmlDsigExcC14NTransform C14NTransformer = new XmlDsigExcC14NTransform(string.Join(" ", prefixes.ToArray()).Trim());
            XmlDsigExcC14NTransform C14NTransformer = new XmlDsigExcC14NTransform();

            reference.AddTransform(C14NTransformer);

            signedXml.AddReference(reference);

            // Add the key to the signature, so the assertion can be verified by itself.
            signedXml.KeyInfo = new KeyInfo();

            // Use RSA key for signing.
            //{
            //    CspParameters parameters = new CspParameters();
            //    parameters.KeyContainerName = "XML_DSIG_RSA_KEY";
            //    RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider(parameters);
            //    signedXml.SigningKey = rsaKey;
            //    signedXml.KeyInfo.AddClause(new RSAKeyValue(rsaKey));
            //}

            // Use X509 Certificate for signing.
            {
                X509Certificate2 cert = new X509Certificate2(@"Saml20\Certificates\sts_dev_certificate.pfx", "test1234");
                Assert.That(cert.HasPrivateKey);
                signedXml.SigningKey = cert.GetRSAPrivateKey();
                signedXml.KeyInfo.AddClause(new KeyInfoX509Data(cert, X509IncludeOption.EndCertOnly));
            }

            // Information on the these and other "key info clause" types can be found at:
            // ms-help://MS.MSDNQTR.v80.en/MS.MSDN.v80/MS.NETDEVFX.v20.en/CPref18/html/T_System_Security_Cryptography_Xml_KeyInfoClause_DerivedTypes.htm

            // Do it!
            signedXml.ComputeSignature();

            XmlNodeList nodes = doc.DocumentElement.GetElementsByTagName("Issuer", Saml20Constants.ASSERTION);
            Assert.That(nodes.Count == 1);
            XmlNode node = nodes[0];
            doc.DocumentElement.InsertAfter(doc.ImportNode(signedXml.GetXml(), true), node);
        }

        /// <summary>
        /// Loads an assertion and tries to deserialize it using the <code>Assertion</code> class.
        /// </summary>
        public static Saml20Assertion DeserializeToken(string assertionFile)
        {
            FileStream fs = File.OpenRead(assertionFile);

            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            document.Load(fs);
            fs.Close();

            XmlNodeList nodes = document.DocumentElement.GetElementsByTagName("Issuer", Saml20Constants.ASSERTION);
            Saml20Assertion assertion = new Saml20Assertion(document.DocumentElement, AssertionUtil.GetTrustedSigners(nodes[0].Value), false);

            return assertion;
        }


        /// <summary>
        /// Loads an assertion and tries to verify it using the key embedded in the assertion.
        /// </summary>
        /// <param name="assertionFile">Path to the file containing the assertion to verify.</param>
        private static bool VerifySignature(string assertionFile)
        {
            FileStream fs = File.OpenRead(assertionFile);

            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            document.Load(fs);

            return VerifySignature(document);
        }

        /// <summary>
        /// Verifies the signature of the assertion contained in the document given as parameter.
        /// </summary>
        private static bool VerifySignature(XmlDocument assertion)
        {
            SignedXml signedXml = new SignedXml(assertion.DocumentElement);

            XmlNodeList nodeList = assertion.GetElementsByTagName(Signature.ELEMENT_NAME, Saml20Constants.XMLDSIG);
            signedXml.LoadXml((XmlElement)nodeList[0]);

            Assert.IsNotNull(signedXml.Signature);

            // Check the signature and return the result.
            /* 
            AsymmetricAlgorithm key;
            bool useEmbeddedKey = signedXml.CheckSignatureReturningKey(out key);
            if (!useEmbeddedKey)
                return false;            

            return signedXml.CheckSignature(key);
            */

            return signedXml.CheckSignature();
        }
    }
}