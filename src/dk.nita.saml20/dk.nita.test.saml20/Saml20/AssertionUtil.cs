using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using dk.nita.saml20;
using dk.nita.saml20.config;
using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.Schema.Metadata;
using dk.nita.saml20.Utils;
using NUnit.Framework;
using Assertion=dk.nita.saml20.Schema.Core.Assertion;

namespace dk.nita.test.Saml20
{
    /// <summary>
    /// Utility class for generating assertions.
    /// </summary>
    public class AssertionUtil
    {
        /// <summary>
        /// Generates an unsigned assertion for use in the other tests.
        /// </summary>
        /// <returns></returns>
        public static XmlDocument GetTestAssertion_01()
        {
            XmlDocument res = new XmlDocument();
            res.PreserveWhitespace = true;
            res.Load(new StringReader(Serialization.SerializeToXmlString(GetBasicAssertion())));
            return res;
        }

        private static X509Certificate2 _cert;

        // The audience-list used for unit tests
        public static List<string> GetAudiences()
        {
            return new List<string>(new string[] { "urn:borger.dk:id" });
        }

        /// <summary>
        /// Retrieve our development certificate.
        /// </summary>        
        public static X509Certificate2 GetCertificate1()
        {
            if (_cert == null)
            {
                _cert = new X509Certificate2(@"Saml20\Certificates\sts_dev_certificate.pfx", "test1234");
                Assert.That(_cert.HasPrivateKey, "Certificate no longer contains a private key. Modify test.");                
            }

            return _cert;
        }

        public static string GetBasicIssuer()
        {
            return "urn:TokenService/Safewhere";
        }
        /// <summary>
        /// Assembles our basic test assertion
        /// </summary>
        /// <returns></returns>
        public static Assertion GetBasicAssertion()
        {
            Assertion assertion = new Assertion();

            {
                assertion.Issuer = new NameID();
                assertion.ID = "_b8977dc86cda41493fba68b32ae9291d";
                assertion.IssueInstant = DateTime.UtcNow;

                assertion.Version = "2.0";
                assertion.Issuer.Value = GetBasicIssuer();
            }

            {
                assertion.Subject = new Subject();
                SubjectConfirmation subjectConfirmation = new SubjectConfirmation();
                subjectConfirmation.Method = SubjectConfirmation.BEARER_METHOD;
                subjectConfirmation.SubjectConfirmationData = new SubjectConfirmationData();
                subjectConfirmation.SubjectConfirmationData.NotOnOrAfter = DateTime.UtcNow.AddMinutes(1);
                subjectConfirmation.SubjectConfirmationData.Recipient = "http://borger.dk";
                assertion.Subject.Items = new object[] { subjectConfirmation };
            }

            {
                assertion.Conditions = new Conditions();
                assertion.Conditions.NotOnOrAfter = DateTime.UtcNow.AddMinutes(1);
                AudienceRestriction audienceRestriction = new AudienceRestriction();
                audienceRestriction.Audience = GetAudiences();
                assertion.Conditions.Items = new List<ConditionAbstract>(new ConditionAbstract[] { audienceRestriction });
            }

            AuthnStatement authnStatement;

            {
                authnStatement = new AuthnStatement();
                assertion.Items = new StatementAbstract[] { authnStatement };
                authnStatement.AuthnInstant = new DateTime(2008, 1, 8);
                authnStatement.SessionIndex = "70225885";
                authnStatement.AuthnContext = new AuthnContext();
                authnStatement.AuthnContext.Items = new object[] { "urn:oasis:names:tc:SAML:2.0:ac:classes:X509", "http://www.safewhere.net/authncontext/declref" };
                authnStatement.AuthnContext.ItemsElementName = new ItemsChoiceType5[] { ItemsChoiceType5.AuthnContextClassRef, ItemsChoiceType5.AuthnContextDeclRef};
            }

            AttributeStatement attributeStatement;
            {
                attributeStatement = new AttributeStatement();
                SamlAttribute surName = new SamlAttribute();
                surName.FriendlyName = "SurName";
                surName.Name = "urn:oid:2.5.4.4";
                surName.NameFormat = SamlAttribute.NAMEFORMAT_URI;
                surName.AttributeValue = new string[] { "Fry" };

                SamlAttribute commonName = new SamlAttribute();
                commonName.FriendlyName = "CommonName";
                commonName.Name = "urn:oid:2.5.4.3";
                commonName.NameFormat = SamlAttribute.NAMEFORMAT_URI;
                commonName.AttributeValue = new string[] { "Philip J. Fry" };

                SamlAttribute userName = new SamlAttribute();
                userName.Name = "urn:oid:0.9.2342.19200300.100.1.1";
                userName.NameFormat = SamlAttribute.NAMEFORMAT_URI;
                userName.AttributeValue = new string[] { "fry" };

                SamlAttribute eMail = new SamlAttribute();
                eMail.FriendlyName = "Email";
                eMail.Name = "urn:oid:0.9.2342.19200300.100.1.3";
                eMail.NameFormat = SamlAttribute.NAMEFORMAT_URI;
                eMail.AttributeValue = new string[] { "fry@planetexpress.com.earth" };

                attributeStatement.Items = new object[] { surName, commonName, userName, eMail };
            }

            assertion.Items = new StatementAbstract[] { authnStatement, attributeStatement };

            return assertion;
        }

        /// <summary>
        /// Returns the saml20Assertion as an XmlDocument as used by the Assertion class.
        /// </summary>
        /// <param name="assertion"></param>
        /// <returns></returns>
        public static XmlDocument ConvertAssertion(Assertion assertion)
        {
            if (assertion == null) throw new ArgumentNullException("assertion");

            XmlDocument res = new XmlDocument();
            res.PreserveWhitespace = true;
            res.Load(new StringReader(Serialization.SerializeToXmlString(assertion)));
            return res;
        }

        /// <summary>
        /// Loads an assertion, deserializes it using the <code>Assertion</code> class and returns the 
        /// resulting <code>Assertion</code> instance.
        /// </summary>
        public static Saml20Assertion DeserializeToken(string assertionFile)
        {
            FileStream fs = File.OpenRead(assertionFile);

            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            document.Load(fs);
            fs.Close();

            Saml20Assertion assertion = new Saml20Assertion(document.DocumentElement, null, false);
            assertion.Validate(DateTime.MinValue);

            List<AsymmetricAlgorithm> result = new List<AsymmetricAlgorithm>(1);
            foreach (KeyInfoClause clause in assertion.GetSignatureKeys())
            {
                AsymmetricAlgorithm key = XmlSignatureUtils.ExtractKey(clause);
                result.Add(key);
            }

            assertion.CheckValid(result);

            return assertion;
        }

        public static Saml20Assertion DeserializeToken(string assertionFile, bool verify)
        {
            if (verify)
                return DeserializeToken(assertionFile);

            FileStream fs = File.OpenRead(assertionFile);

            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            document.Load(fs);
            fs.Close();

            Saml20Assertion assertion = new Saml20Assertion(document.DocumentElement, null, false);
            assertion.Validate(DateTime.MinValue);
            return assertion;
        }

        public static IEnumerable<AsymmetricAlgorithm> GetTrustedSigners(string issuer)
        {
            if (issuer == null)
                throw new ArgumentNullException("issuer");

            SAML20FederationConfig config = SAML20FederationConfig.GetConfig();
            IDPEndPoint idpEndpoint = config.FindEndPoint(issuer);
            if (idpEndpoint == null)
                throw new InvalidOperationException(String.Format("No idp endpoint found for issuer {0}", issuer));

            if (idpEndpoint.metadata == null)
                throw new InvalidOperationException(String.Format("No metadata found for issuer {0}", issuer));

            if (idpEndpoint.metadata.Keys == null)
                throw new InvalidOperationException(String.Format("No key descriptors found in metadata found for issuer {0}", issuer));

            List<AsymmetricAlgorithm> result = new List<AsymmetricAlgorithm>(1);
            foreach (KeyDescriptor key in idpEndpoint.metadata.Keys)
            {
                KeyInfo ki = (KeyInfo) key.KeyInfo;
                foreach (KeyInfoClause clause in ki)
                {
                    AsymmetricAlgorithm aa = XmlSignatureUtils.ExtractKey(clause);
                    result.Add(aa);
                }
            }

            return result;
        }
    }
}