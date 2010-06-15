using System.Collections.Generic;
using dk.nita.saml20.Profiles.DKSaml20;
using dk.nita.saml20.Schema.Core;

namespace dk.nita.saml20.Validation
{
    internal class DKSaml20AssertionValidator : Saml20AssertionValidator
    {
        
        public DKSaml20AssertionValidator(List<string> allowedAudienceUris, bool quirksMode)
            : base(allowedAudienceUris, quirksMode)
        {}

        #region Properties

        private ISaml20SubjectValidator _subjectValidator;

        private ISaml20SubjectValidator SubjectValidator
        {
            get
            {
                if (_subjectValidator == null)
                    _subjectValidator = new DKSaml20SubjectValidator();
                return _subjectValidator;
            }
        }

        private ISaml20StatementValidator _statementValidator;

        private ISaml20StatementValidator StatementValidator
        {
            get
            {
                if (_statementValidator == null)
                    _statementValidator = new DKSaml20StatementValidator();
                return _statementValidator;
            }
        }

        #endregion


        /// <summary>
        /// Validates the saml20Assertion to make sure it conforms to the DK-Saml 2.0 profile.
        /// </summary>
        /// <param name="assertion">The assertion to validate.</param>
        public override void ValidateAssertion(Assertion assertion)
        {
            base.ValidateAssertion(assertion);

            ValidateIssuerElement(assertion);
            ValidateStatements(assertion);
            ValidateSubject(assertion);
            ValidateConditions(assertion); 
        }

        /// <summary>
        /// Validates the saml20Assertion's list of conditions.
        /// </summary>
        private void ValidateConditions(Assertion saml20Assertion)
        {
            bool audienceRestrictionPresent = false;
            foreach (ConditionAbstract condition in saml20Assertion.Conditions.Items)
            {
                if (condition is AudienceRestriction)
                {
                    audienceRestrictionPresent = true;
                    AudienceRestriction audienceRestriction = (AudienceRestriction)condition;
                    if (audienceRestriction.Audience == null || audienceRestriction.Audience.Count == 0)
                        throw new DKSaml20FormatException(
                            "The DK-SAML 2.0 profile requires that an \"AudienceRestriction\" element contains the service provider's unique identifier in an \"Audience\" element.");
                }
            }

            if (!audienceRestrictionPresent)
                throw new DKSaml20FormatException("The DK-SAML 2.0 profile requires that an \"AudienceRestriction\" element is present on the saml20Assertion.");
        }

        /// <summary>
        /// Ensures that a "subject" is present in the saml20Assertion, and validates the subject.
        /// </summary>
        private void ValidateSubject(Assertion assertion)
        {
            if (assertion.Subject == null)
                throw new DKSaml20FormatException("The DK-SAML 2.0 profile requires that a \"Subject\" element is present in the saml20Assertion.");

            SubjectValidator.ValidateSubject(assertion.Subject);
        }

        /// <summary>
        /// Ensures that there are no AuthzdecisionStatement in the DK-SAML20 assertion.
        /// </summary>
        private void ValidateStatements(Assertion assertion)
        {
            // TODO If no attributes are requested, the assertion will not contain an AttributeStatement instance. Rethink this validation.

            // Check that the number of statements is correct.
            if (assertion.Items.Length != 2)
                throw new DKSaml20FormatException("The DK-SAML 2.0 profile requires exactly one \"AuthnStatement\" element and one \"AttributeStatement\" element.");

            // Check if it is the correct statements.            
            bool authnStatementPresent = false;
            bool attributeStatementPresent = false;
            foreach (StatementAbstract statement in assertion.Items)
            {
                StatementValidator.ValidateStatement(statement);

                if (statement is AuthnStatement)
                    authnStatementPresent = true;

                if (statement is AttributeStatement)
                    attributeStatementPresent = true;
            }

            if (!(authnStatementPresent && attributeStatementPresent))
                throw new DKSaml20FormatException("The DK-SAML 2.0 profile requires exactly one \"AuthnStatement\" element and one \"AttributeStatement\" element.");            
        }

        /// <summary>
        /// Checks that the signature element does not contain any attributes, as ordered in the DK SAML 2.0 profile.
        /// </summary>
        private void ValidateIssuerElement(Assertion assertion)
        {
            if (assertion.Issuer == null)
                throw new DKSaml20FormatException("Assertion MUST contain an issuer in the DK-SAML 2.0 profile.");
            
            // KBP 01-09-2008: Removed validation of attributes on Issuer element due to future changes DK-SAML profile.
        }

        /// <summary>
        /// Throws a DKSaml20FormationException containing an error message saying that an Issuer-element cannot have 
        /// attributes in the DK-SAML 2.0 profile.
        /// </summary>
        private static void ThrowIssuerNotEntity()
        {
            throw new DKSaml20FormatException(
                "The DK-SAML 2.0 Profile does not allow the \"Issuer\" element to have any attributes."); 
        }

    }
}
