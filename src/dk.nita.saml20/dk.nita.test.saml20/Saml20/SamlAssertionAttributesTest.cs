using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using dk.nita.saml20;
using dk.nita.saml20.Profiles.DKSaml20.Attributes;
using dk.nita.saml20.Schema.Core;
using NUnit.Framework;

namespace dk.nita.test.Saml20
{
    /// <summary>
    /// Tests related to the handling of attributes on Saml Assertions.
    /// </summary>
    [TestFixture]
    public class SamlAssertionAttributesTest
    {
        #region Tests

        /// <summary>
        /// Load one of the test assertions and verify its number of attributes.
        /// </summary>
        [Test]
        public void ReadAttributes_01()
        {
            Saml20Assertion assertion = LoadAssertion(@"Saml20\Assertions\Saml2Assertion_01");
            CollectionAssert.IsNotEmpty(assertion.Attributes);
            Assert.AreEqual(4, assertion.Attributes.Count);
            foreach(SamlAttribute sa in assertion.Attributes)
            {
                Assert.That(sa.AttributeValue.Length != 0, "Attribute should have a value");
                Assert.That(sa.AttributeValue[0] is string, "Attribute value must be a string");
            }
        }

        #endregion

        /// <summary>
        /// Creates a DKSaml20-token from a file. The token's signature is NOT verified on load.
        /// </summary>
        internal Saml20Assertion LoadAssertion(string file)
        {
            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            document.Load(file);

            return new Saml20Assertion(document.DocumentElement, null, false);
        }
    }
}