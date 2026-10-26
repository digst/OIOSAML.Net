using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using dk.nita.saml20.Schema.Metadata;
using dk.nita.saml20.Schema.Protocol;
using dk.nita.saml20.Utils;
using NUnit.Framework;
using dk.nita.saml20.config;
using dk.nita.saml20;
using dk.nita.saml20.protocol;
using Assertion=dk.nita.saml20.Schema.Core.Assertion;
using Saml20Assertion=dk.nita.saml20.Saml20Assertion;

namespace dk.nita.test.Saml20
{
    /// <summary>
    /// Unit tests related to the handling and functionality of encrypted assertions.
    /// </summary>
    [TestFixture]
    public class EncryptedAssertionTest
    {    
        private static Saml20Assertion CreateDKSaml20TokenFromAssertion(Saml20EncryptedAssertion encAss)
        {
            return new Saml20Assertion(encAss.Assertion.DocumentElement, null, false);
        }

        /// <summary>
        /// Loads an encrypted assertion, retrieves the symmetric key used for its encryption and decrypts it.
        /// </summary>
        [Test]
        public void DecryptAssertion_01()
        {
            DecryptAssertion(@"Saml20\Assertions\EncryptedAssertion_01");
        }

        /// <summary>
        /// An example on how to decrypt an encrypted assertion.
        /// </summary>
        private static void DecryptAssertion(string file)
        {            
            XmlDocument doc = new XmlDocument();
            doc.Load(file);            
            XmlElement encryptedDataElement = GetElement(dk.nita.saml20.Schema.XEnc.EncryptedData.ELEMENT_NAME, Saml20Constants.XENC, doc);                        

            
            EncryptedData encryptedData = new EncryptedData();
            encryptedData.LoadXml(encryptedDataElement);

            XmlNodeList nodelist = doc.GetElementsByTagName(dk.nita.saml20.Schema.XmlDSig.KeyInfo.ELEMENT_NAME, Saml20Constants.XMLDSIG);
            Assert.That(nodelist.Count > 0);

            KeyInfo key = new KeyInfo();
            key.LoadXml((XmlElement) nodelist[0]);

            // Review: Is it possible to figure out which certificate to load based on the Token?
            /*
             * Comment:
             * It would be possible to provide a key/certificate identifier in the EncryptedKey element, which contains the "recipient" attribute.
             * The implementation (Safewhere.Tokens.Saml20.Saml20EncryptedAssertion) currently just expects an appropriate asymmetric key to be provided,
             * and is not not concerned about its origin. 
             * If the need arises, we can easily extend the Saml20EncryptedAssertion class with a property that allows extraction key info, eg. the "recipient" 
             * attribute.
             */
            X509Certificate2 cert = new X509Certificate2(@"Saml20\Certificates\sts_dev_certificate.pfx", "test1234");

            // ms-help://MS.MSDNQTR.v80.en/MS.MSDN.v80/MS.NETDEVFX.v20.en/CPref18/html/T_System_Security_Cryptography_Xml_KeyInfoClause_DerivedTypes.htm
            // Look through the list of KeyInfo elements to find the encrypted key.
            SymmetricAlgorithm symmetricKey = null;
            foreach (KeyInfoClause keyInfoClause in key)
            {
                if (keyInfoClause is KeyInfoEncryptedKey)
                {
                    KeyInfoEncryptedKey keyInfoEncryptedKey = (KeyInfoEncryptedKey) keyInfoClause;
                    EncryptedKey encryptedKey = keyInfoEncryptedKey.EncryptedKey;
                    symmetricKey = new RijndaelManaged();
                                        
                    symmetricKey.Key =
                        EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, (RSA) cert.PrivateKey, false);
                    continue;
                }
            }
            // Explode if we didn't manage to find a viable key.
            Assert.IsNotNull(symmetricKey);
            EncryptedXml encryptedXml = new EncryptedXml();
            byte[] plaintext = encryptedXml.DecryptData(encryptedData, symmetricKey);

            XmlDocument assertion = new XmlDocument();
            assertion.Load(new StringReader(System.Text.Encoding.UTF8.GetString(plaintext)));

            // A very simple test to ensure that there is indeed an assertion in the plaintext.
            Assert.AreEqual(Assertion.ELEMENT_NAME, assertion.DocumentElement.LocalName);
            Assert.AreEqual(Saml20Constants.ASSERTION, assertion.DocumentElement.NamespaceURI);
        }

        /// <summary>
        /// Generates an encrypted assertion and writes it to disk. 
        /// </summary>
        [Test]
        public void GenerateEncryptedAssertion_01()
        {
            XmlDocument assertion = AssertionUtil.GetTestAssertion_01();

            // Create an EncryptedData instance to hold the results of the encryption.o
            EncryptedData encryptedData = new EncryptedData();
            encryptedData.Type = EncryptedXml.XmlEncElementUrl;
            encryptedData.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);

            // Create a symmetric key. 
            RijndaelManaged aes = new RijndaelManaged();
            aes.KeySize = 256;
            aes.GenerateKey();

            // Encrypt the assertion and add it to the encryptedData instance.
            EncryptedXml encryptedXml = new EncryptedXml();
            byte[] encryptedElement = encryptedXml.EncryptData(assertion.DocumentElement, aes, false);
            encryptedData.CipherData.CipherValue = encryptedElement;

            // Add an encrypted version of the key used.
            encryptedData.KeyInfo = new KeyInfo();

            EncryptedKey encryptedKey = new EncryptedKey();

            // Use this certificate to encrypt the key.
            X509Certificate2 cert = new X509Certificate2(@"Saml20\Certificates\sts_dev_certificate.pfx", "test1234");
            RSA publicKeyRSA = cert.PublicKey.Key as RSA;
            Assert.IsNotNull(publicKeyRSA, "Public key of certificate was not an RSA key. Modify test.");
            encryptedKey.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url);
            encryptedKey.CipherData = new CipherData(EncryptedXml.EncryptKey(aes.Key, publicKeyRSA, false));


            encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));

            // Create the resulting Xml-document to hook into.
            EncryptedAssertion encryptedAssertion = new EncryptedAssertion();
            encryptedAssertion.encryptedData = new saml20.Schema.XEnc.EncryptedData();
            encryptedAssertion.encryptedKey = new saml20.Schema.XEnc.EncryptedKey[1];
            encryptedAssertion.encryptedKey[0] = new saml20.Schema.XEnc.EncryptedKey();

            XmlDocument result;
            result = Serialization.Serialize(encryptedAssertion);            

            XmlElement encryptedDataElement = GetElement(dk.nita.saml20.Schema.XEnc.EncryptedData.ELEMENT_NAME, Saml20Constants.XENC, result);
            EncryptedXml.ReplaceElement(encryptedDataElement, encryptedData, false);
        }        

        /// <summary>
        /// The sample assertions are encrypted with algorithms that [OIO-ALG-01] doesn't allow, so they are refused.
        /// </summary>
        [TestCase(@"Saml20\Assertions\EncryptedAssertion_01", Description = "AES-256-CBC with RSA-1.5 key transport")]
        [TestCase(@"Saml20\Assertions\EncryptedAssertion_02", Description = "AES-256-CBC with RSA-1.5, key next to the data")]
        [TestCase(@"Saml20\Assertions\EncryptedAssertion_03", Description = "no key transport algorithm")]
        [TestCase(@"Saml20\Assertions\EncryptedAssertion_04", Description = "3DES")]
        [TestCase(@"Saml20\Assertions\EncryptedAssertion_05", Description = "AES-192-CBC")]
        public void AssertionEncryptedWithAnAlgorithmThatIsNotAllowedIsRefused(string file)
        {
            XmlDocument doc = new XmlDocument();
            doc.Load(File.OpenRead(file));
            X509Certificate2 cert = new X509Certificate2(@"Saml20\Certificates\sts_dev_certificate.pfx", "test1234");

            Saml20EncryptedAssertion encryptedAssertion = new Saml20EncryptedAssertion((RSA)cert.PrivateKey, doc);

            Assert.Throws<Saml20Exception>(() => encryptedAssertion.Decrypt());
            Assert.IsNull(encryptedAssertion.Assertion);
        }

        private static readonly X509Certificate2 SpCertificate = new X509Certificate2(@"Saml20\Certificates\sts_dev_certificate.pfx", "test1234");

        /// <summary>
        /// Encrypts content as an EncryptedAssertion for the test SP certificate.
        /// </summary>
        private static XmlDocument EncryptAssertion(string content, string dataAlgorithm, string keyAlgorithm, string oaepDigest = null)
        {
            SymmetricAlgorithm key;
            if (dataAlgorithm == EncryptedXml.XmlEncTripleDESUrl)
            {
                key = TripleDES.Create();
            }
            else
            {
                key = new RijndaelManaged();
                key.KeySize = dataAlgorithm == EncryptedXml.XmlEncAES128Url ? 128 : dataAlgorithm == EncryptedXml.XmlEncAES192Url ? 192 : 256;
            }
            key.GenerateKey();

            var encryptedData = new EncryptedData
            {
                Type = EncryptedXml.XmlEncElementUrl,
                EncryptionMethod = new EncryptionMethod(dataAlgorithm),
                CipherData = new CipherData(new EncryptedXml().EncryptData(System.Text.Encoding.UTF8.GetBytes(content), key)),
            };

            var rsa = SpCertificate.GetRSAPublicKey();
            var encryptedKey = new EncryptedKey
            {
                EncryptionMethod = keyAlgorithm == null ? null : new EncryptionMethod(keyAlgorithm),
                CipherData = new CipherData(EncryptedXml.EncryptKey(key.Key, rsa, keyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl)),
            };
            encryptedData.KeyInfo = new KeyInfo();
            encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));

            var doc = new XmlDocument { PreserveWhitespace = true };
            var root = doc.CreateElement("saml", "EncryptedAssertion", Saml20Constants.ASSERTION);
            doc.AppendChild(root);
            root.AppendChild(doc.ImportNode(encryptedData.GetXml(), true));

            if (oaepDigest != null)
            {
                var method = (XmlElement)root.GetElementsByTagName("EncryptionMethod", Saml20Constants.XENC).Cast<XmlElement>()
                    .Single(m => m.GetAttribute("Algorithm") == keyAlgorithm);
                var digest = doc.CreateElement("ds", "DigestMethod", Saml20Constants.XMLDSIG);
                digest.SetAttribute("Algorithm", oaepDigest);
                method.AppendChild(digest);
            }

            return doc;
        }

        private static Saml20EncryptedAssertion Decrypt(XmlDocument encrypted)
        {
            var encryptedAssertion = new Saml20EncryptedAssertion(SpCertificate.GetRSAPrivateKey(), encrypted);
            encryptedAssertion.Decrypt();
            return encryptedAssertion;
        }

        private static string TestAssertion => AssertionUtil.GetTestAssertion_01().DocumentElement.OuterXml;

        [TestCase(EncryptedXml.XmlEncAES128Url)]
        [TestCase(EncryptedXml.XmlEncAES256Url)]
        public void AssertionEncryptedWithAesCbcAndRsaOaepIsDecrypted(string dataAlgorithm)
        {
            var decrypted = Decrypt(EncryptAssertion(TestAssertion, dataAlgorithm, EncryptedXml.XmlEncRSAOAEPUrl));

            Assert.AreEqual(Assertion.ELEMENT_NAME, decrypted.Assertion.DocumentElement.LocalName);
        }

        [Test]
        public void RsaOaepWithItsDefaultSha1DigestIsDecrypted()
        {
            var decrypted = Decrypt(EncryptAssertion(TestAssertion, EncryptedXml.XmlEncAES256Url, EncryptedXml.XmlEncRSAOAEPUrl, SignedXml.XmlDsigSHA1Url));

            Assert.IsNotNull(decrypted.Assertion);
        }

        [TestCase(EncryptedXml.XmlEncAES256Url, EncryptedXml.XmlEncRSA15Url, Description = "RSA-1.5 key transport")]
        [TestCase(EncryptedXml.XmlEncAES256Url, null, Description = "no key transport algorithm")]
        [TestCase(EncryptedXml.XmlEncTripleDESUrl, EncryptedXml.XmlEncRSAOAEPUrl, Description = "3DES")]
        [TestCase(EncryptedXml.XmlEncAES192Url, EncryptedXml.XmlEncRSAOAEPUrl, Description = "AES-192-CBC")]
        public void AlgorithmThatIsNotAllowedIsRefused(string dataAlgorithm, string keyAlgorithm)
        {
            Assert.Throws<Saml20Exception>(() => Decrypt(EncryptAssertion(TestAssertion, dataAlgorithm, keyAlgorithm)));
        }

        [Test]
        public void RsaOaepWithAnotherDigestIsRefused()
        {
            Assert.Throws<Saml20Exception>(() => Decrypt(EncryptAssertion(TestAssertion, EncryptedXml.XmlEncAES256Url, EncryptedXml.XmlEncRSAOAEPUrl, SignedXml.XmlDsigSHA256Url)));
        }

        [Test]
        public void DecryptedContentWithADtdIsRefused()
        {
            var content = "<!DOCTYPE Assertion [<!ENTITY e \"x\">]>" + TestAssertion;

            Assert.Throws<Saml20FormatException>(() => Decrypt(EncryptAssertion(content, EncryptedXml.XmlEncAES256Url, EncryptedXml.XmlEncRSAOAEPUrl)));
        }

        [Test]
        public void DecryptedContentWithMoreThanOneAssertionIsRefused()
        {
            var assertion = AssertionUtil.GetTestAssertion_01();
            var nested = assertion.ImportNode(AssertionUtil.GetTestAssertion_01().DocumentElement, true);
            assertion.DocumentElement.AppendChild(nested);

            Assert.Throws<Saml20FormatException>(() => Decrypt(EncryptAssertion(assertion.DocumentElement.OuterXml, EncryptedXml.XmlEncAES256Url, EncryptedXml.XmlEncRSAOAEPUrl)));
        }

        [Test]
        public void DecryptedContentThatIsNotAnAssertionIsRefused()
        {
            Assert.Throws<Saml20FormatException>(() => Decrypt(EncryptAssertion("<foo/>", EncryptedXml.XmlEncAES256Url, EncryptedXml.XmlEncRSAOAEPUrl)));
        }

        /// <summary>
        /// Tests that it is possible to specify the algorithm of the session key.
        /// </summary>
        [Test]
        [ExpectedException(typeof(ArgumentException))]
        public void TestAlgorithmConfiguration_01()
        {
            Saml20EncryptedAssertion encryptedAssertion = new Saml20EncryptedAssertion();
            encryptedAssertion.SessionKeyAlgorithm = "RSA";
            Assert.Fail("\"Saml20EncryptedAssertion\" class does not respond to incorrect algorithm identifying URI.");
        }

        

        private static XmlElement GetElement(string element, string ns, XmlDocument doc)
        {
            XmlNodeList list = doc.GetElementsByTagName(element, ns);
            Assert.That(list.Count == 1);

            return (XmlElement)list[0];
        }
    }
}