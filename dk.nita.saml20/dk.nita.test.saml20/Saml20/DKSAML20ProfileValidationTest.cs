using System;
using System.Collections.Generic;
using System.Xml;
using dk.nita.saml20.Profiles.DKSaml20;
using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.Schema.Protocol;
using dk.nita.saml20.Schema.XEnc;
using NUnit.Framework;
using dk.nita.saml20;
using dk.nita.saml20.Validation;
using Assertion=dk.nita.saml20.Schema.Core.Assertion;

namespace dk.nita.test.Saml20
{
    /// <summary>
    /// This fixture tests that the DK-SAML20 classes comply with the DK-SAML20 profile.
    /// </summary>
    [TestFixture]
    public class DKSAML20ProfileValidationTest
    {
        private readonly DKSaml20AssertionValidator _validator;

        public DKSAML20ProfileValidationTest()
        {
            _validator = new DKSaml20AssertionValidator(AssertionUtil.GetAudiences(),false);
        }

        #region Tests

        /// <summary>
        /// Test that we are able to retrieve the value of the &lt;Issuer&gt; element.
        /// </summary>
        [Test]
        public void TestRetrieveIssuer()
        {
            Saml20Assertion assertion = AssertionUtil.DeserializeToken(@"Saml20\Assertions\Saml2Assertion_01", false);
            Assert.AreEqual("TokenService/Safewhere", assertion.Issuer);
        }

        /// <summary>
        /// Test that EncryptedData element with the correct Type value is disallowed by the DK Saml 2.0 validation
        /// </summary>        
        [Test]
        [ExpectedException(typeof(DKSaml20FormatException), ExpectedMessage = "The DK-SAML 2.0 profile does not allow encrypted attributes.")]
        public void AttributeStatement_Invalid_EncryptedAttribute_DKSaml20()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            AttributeStatement sas = GetAttributeStatement(statements);
            List<object> attributes = new List<object>(sas.Items);
            EncryptedElement ee = new EncryptedElement();
            ee.encryptedData = new EncryptedData();
            ee.encryptedData.Type = Saml20Constants.XENC + "Element";
            attributes.Add(ee);
            sas.Items = attributes.ToArray();
            saml20Assertion.Items = statements.ToArray();

            XmlDocument doc = AssertionUtil.ConvertAssertion(saml20Assertion);
            new Saml20Assertion(doc.DocumentElement, null, false);
        }

        /// <summary>
        /// Add an &lt;AuthzDecisionStatement&gt; to the list of statements and check that this is detected as a violation.
        /// </summary>
        [Test]
        [ExpectedException(typeof(DKSaml20FormatException), ExpectedMessage = "The DK-SAML 2.0 profile requires exactly one \"AuthnStatement\" element and one \"AttributeStatement\" element.")]        
        public void AttributeStatement_Invalid_Statementtype()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            AuthzDecisionStatement authzDecisionStatement = new AuthzDecisionStatement();
            authzDecisionStatement.Decision = DecisionType.Permit;
            authzDecisionStatement.Resource = "http://safewhere.net";
            authzDecisionStatement.Action = new Action[] { new Action() };            
            authzDecisionStatement.Action[0].Namespace = "http://actionns.com";
            authzDecisionStatement.Action[0].Value = "value";

            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            statements.Add(authzDecisionStatement);

            saml20Assertion.Items = statements.ToArray();

            new Saml20Assertion(AssertionUtil.ConvertAssertion(saml20Assertion).DocumentElement, null, false);
        }

        /// <summary>
        /// Verify that an assertion without an &lt;Issuser&gt; element is considered is detected as a violation.
        /// 
        /// Section 7.1.2 of [DKSAML].
        /// 
        /// 01-09-2008 This test is now obsolete.
        /// 
        /// </summary>
        //[Test]
        //public void Issuer_Element()
        //{
        //    Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
        //    Assert.IsNotNull(saml20Assertion.Issuer);
        //    saml20Assertion.Issuer = null;

        //    TestAssertion(saml20Assertion, "Assertion element must have an issuer element.");            

        //    saml20Assertion.Issuer = new NameID();            
        //    saml20Assertion.Issuer.Value = "http://safewhere.net";
        //    saml20Assertion.Issuer.Format = "http://example.com";

        //    TestAssertion(saml20Assertion, "The DK-SAML 2.0 Profile does not allow the \"Issuer\" element to have any attributes.");
            
        //    saml20Assertion.Issuer.Format = null;
        //    saml20Assertion.Issuer.NameQualifier = "NameQualifier";

        //    TestAssertion(saml20Assertion, "The DK-SAML 2.0 Profile does not allow the \"Issuer\" element to have any attributes.");

        //    saml20Assertion.Issuer.NameQualifier = null;
        //    saml20Assertion.Issuer.SPNameQualifier = "SPNameQualifier";

        //    TestAssertion(saml20Assertion, "The DK-SAML 2.0 Profile does not allow the \"Issuer\" element to have any attributes.");
            
        //    saml20Assertion.Issuer.SPNameQualifier = null;
        //    saml20Assertion.Issuer.SPProvidedID = "SPProvidedID";

        //    TestAssertion(saml20Assertion, "The DK-SAML 2.0 Profile does not allow the \"Issuer\" element to have any attributes.");
        //}

        [Test]
        public void Issuer_Element_QuirksMode()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            Assert.IsNotNull(saml20Assertion.Issuer);

            saml20Assertion.Issuer = new NameID();
            saml20Assertion.Issuer.Value = "http://safewhere.net";
            saml20Assertion.Issuer.Format = "http://example.com";

            DKSaml20AssertionValidator quirksModeValidator = new DKSaml20AssertionValidator(AssertionUtil.GetAudiences(), true);

            try
            {
                quirksModeValidator.ValidateAssertion(saml20Assertion);
            }
            catch (Exception e)
            {
                Assert.That(false, "The above validation should not fail in quirksMode: " + e.ToString());
            }
        }

        /// <summary>
        /// Verify the rules for the &lt;Subject&gt; element, which are outlined in section 7.1.4 of [DKSAML]
        /// </summary>
        [Test]
        public void Subject_Element()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            Assert.IsNotNull(saml20Assertion.Subject);

            Assert.That(saml20Assertion.Subject.Items.Length > 0);

            SubjectConfirmation subjectConfirmation = 
                (SubjectConfirmation) Array.Find(saml20Assertion.Subject.Items, delegate(object item) { return item is SubjectConfirmation; });
            Assert.IsNotNull(subjectConfirmation);
            string originalMethod = subjectConfirmation.Method;
            subjectConfirmation.Method = "IllegalMethod";

            TestAssertion(saml20Assertion, "SubjectConfirmation element has Method attribute which is not a wellformed absolute uri.");
            // Try a valid url.
            subjectConfirmation.Method = "http://example.com";
            TestAssertion(saml20Assertion, "The DK-SAML 2.0 Profile requires that a bearer \"SubjectConfirmation\" element is present.");

            // Restore valid settings... And verify that it is restored.
            subjectConfirmation.Method = originalMethod;
            TestAssertion(saml20Assertion, null);

            // Now, start messing with the <SubjectConfirmationData> element.
            subjectConfirmation.SubjectConfirmationData.NotOnOrAfter = null;
            TestAssertion(saml20Assertion, "The DK-SAML 2.0 Profile requires that the \"SubjectConfirmationData\" element contains the \"NotOnOrAfter\" attribute.");
            subjectConfirmation.SubjectConfirmationData.NotOnOrAfter = DateTime.UtcNow;

            subjectConfirmation.SubjectConfirmationData.NotBefore = DateTime.UtcNow.Subtract(new TimeSpan(5,0,0,0));
            TestAssertion(saml20Assertion, "The DK-SAML 2.0 Profile disallows the use of the \"NotBefore\" attribute of the \"SubjectConfirmationData\" element.");

            subjectConfirmation.SubjectConfirmationData.NotBefore = null;

            string originalRecipient = subjectConfirmation.SubjectConfirmationData.Recipient;
            subjectConfirmation.SubjectConfirmationData.Recipient = null;
            TestAssertion(saml20Assertion, "The DK-SAML 2.0 Profile requires that the \"SubjectConfirmationData\" element contains the \"Recipient\" attribute.");
            subjectConfirmation.SubjectConfirmationData.Recipient = originalRecipient;

            saml20Assertion.Subject = null;
            TestAssertion(saml20Assertion, "AuthnStatement, AuthzDecisionStatement and AttributeStatement require a subject.");
        }

        /// <summary>
        /// Verify the rules for the &lt;Conditions&gt; element, which are outlined in section 7.1.5 of [DKSAML]
        /// </summary>
        [Test]
        public void Conditions_Element()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            Assert.IsNotNull(saml20Assertion.Conditions);
            List<ConditionAbstract> conditions =
                new List<ConditionAbstract>(saml20Assertion.Conditions.Items);

            int index = conditions.FindIndex(delegate(ConditionAbstract cond) { return cond is AudienceRestriction; });
            Assert.That( index != -1);
            conditions.RemoveAt(index);
            // Add another condition to avoid an empty list of conditions.
            conditions.Add( new OneTimeUse());
            saml20Assertion.Conditions.Items = conditions;

            TestAssertion(saml20Assertion, "The DK-SAML 2.0 profile requires that an \"AudienceRestriction\" element is present on the saml20Assertion.");
        }

        /// <summary>
        /// Verify the rules for the &lt;AuthnStatement&gt; element, which are outlined in section 7.1.7 of [DKSAML]
        /// </summary>
        [Test]        
        public void AuthnStatement_Element()
        {
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();
            AuthnStatement authnStmt =
                (AuthnStatement)Array.Find(saml20Assertion.Items, delegate(StatementAbstract stmnt) { return stmnt is AuthnStatement; });

            // Mess around with the AuthnStatement.
            {
                string oldSessionIndex = authnStmt.SessionIndex;
                authnStmt.SessionIndex = null;
                TestAssertion(saml20Assertion, "The DK-SAML 2.0 profile requires that the \"AuthnStatement\" element contains the \"SessionIndex\" attribute.");
                authnStmt.SessionIndex = oldSessionIndex;
            }

            {
                int index = 
                    Array.FindIndex(authnStmt.AuthnContext.Items, 
                                    delegate(object o) { return o is string && o.ToString() == "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"; });
                object oldValue = authnStmt.AuthnContext.Items[index];
                authnStmt.AuthnContext.Items[index] = "Hallelujagobble!!";
                TestAssertion(saml20Assertion, "AuthnContextClassRef has a value which is not a wellformed absolute uri");
                authnStmt.AuthnContext.Items[index] = oldValue;
            }

            // Remove it.
            saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            statements.RemoveAll(delegate(StatementAbstract stmnt) { return stmnt is AuthnStatement; });
            saml20Assertion.Items = statements.ToArray();
            TestAssertion(saml20Assertion, "The DK-SAML 2.0 profile requires exactly one \"AuthnStatement\" element and one \"AttributeStatement\" element.");
        }

        /// <summary>
        /// Verify the rules for the &lt;AttributeStatement&gt; element, which are outlined in section 7.1.8 of [DKSAML]
        /// </summary>
        [Test]        
        public void AttributeStatement_Element()
        {            
            Predicate<StatementAbstract> findAttributeStatement =
                delegate(StatementAbstract stmnt) { return stmnt is AttributeStatement; };
            Assertion saml20Assertion = AssertionUtil.GetBasicAssertion();

            AttributeStatement attributeStatement =
                (AttributeStatement) Array.Find(saml20Assertion.Items, findAttributeStatement);           

            // Add an encrypted attribute.
            EncryptedElement encAtt = new EncryptedElement();
            encAtt.encryptedData = new EncryptedData();
            encAtt.encryptedData.CipherData = new CipherData();
            encAtt.encryptedData.CipherData.Item = string.Empty;
            encAtt.encryptedKey = new EncryptedKey[0];
            attributeStatement.Items = new object[] { encAtt };
            TestAssertion(saml20Assertion, "The DK-SAML 2.0 profile does not allow encrypted attributes.");

            // Add an attribute with the wrong nameformat.
//            Attribute att = DKSaml20EmailAttribute.create("test@example.com");
//            att.NameFormat = "http://example.com";
//            attributeStatement.Items = new object[] { att };
//            testAssertion(saml20Assertion, "The DK-SAML 2.0 profile requires that an attribute's \"NameFormat\" element is urn:oasis:names:tc:SAML:2.0:attrname-format:uri.");

            // Clear all the attributes.
            attributeStatement.Items = new object[0];
            TestAssertion(saml20Assertion, "AttributeStatement MUST contain at least one Attribute or EncryptedAttribute");            

            // Remove it.
            saml20Assertion = AssertionUtil.GetBasicAssertion();
            List<StatementAbstract> statements = new List<StatementAbstract>(saml20Assertion.Items);
            statements.RemoveAll(findAttributeStatement);
            saml20Assertion.Items = statements.ToArray();
            TestAssertion(saml20Assertion, "The DK-SAML 2.0 profile requires exactly one \"AuthnStatement\" element and one \"AttributeStatement\" element.");
        }

        #endregion

        private void TestAssertion(Assertion saml20Assertion, string exceptionMsg)
        {
            try
            {
                _validator.ValidateAssertion(saml20Assertion);
                if (!string.IsNullOrEmpty(exceptionMsg))
                    Assert.Fail("A validation exception should have been thrown.");
            }
            catch (Saml20FormatException e)
            {
                Console.WriteLine('"' + e.Message.Replace("\"", "\\\"") + '"');
                Assert.AreEqual(exceptionMsg, e.Message);
            }
        }

        /// <summary>
        /// Convenience method for extracting the list of Attributes from the assertion.
        /// </summary>
        /// <param name="statements"></param>
        /// <returns></returns>
        private static AttributeStatement GetAttributeStatement(List<StatementAbstract> statements)
        {            
            return (AttributeStatement) statements.Find(delegate(StatementAbstract ssa) { return ssa is AttributeStatement; });
        }
    }
}