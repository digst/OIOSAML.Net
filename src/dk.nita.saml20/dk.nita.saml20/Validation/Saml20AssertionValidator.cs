using System;
using System.Collections.Generic;
using System.Diagnostics;
using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.Utils;
using Trace = dk.nita.saml20.Utils.Trace;

namespace dk.nita.saml20.Validation
{
    internal class Saml20AssertionValidator : ISaml20AssertionValidator
    {
        private readonly List<string> _allowedAudienceUris;
        protected bool _quirksMode;

        public Saml20AssertionValidator(List<string> allowedAudienceUris, bool quirksMode)
        {
            _allowedAudienceUris = allowedAudienceUris;
            _quirksMode = quirksMode;
        }

        #region Properties

        private ISaml20NameIDValidator _nameIDValidator;

        private ISaml20NameIDValidator NameIDValidator
        {
            get
            {
                if (_nameIDValidator == null)
                    _nameIDValidator = new Saml20NameIDValidator();
                return _nameIDValidator;
            }
        }

        private ISaml20SubjectValidator _subjectValidator;

        private ISaml20SubjectValidator SubjectValidator
        {
            get
            {
                if (_subjectValidator == null)
                    _subjectValidator = new Saml20SubjectValidator();
                return _subjectValidator;
            }
        }

        private ISaml20StatementValidator StatementValidator
        {
            get
            {
                if (_statementValidator == null)
                    _statementValidator = new Saml20StatementValidator();

                return _statementValidator;
            }
        }

        private ISaml20StatementValidator _statementValidator;
        #endregion

        #region ISaml20AssertionValidator interface

        public virtual void ValidateAssertion(Assertion assertion)
        {
            if (assertion == null) throw new ArgumentNullException("assertion");

            ValidateAssertionAttributes(assertion);
            ValidateSubject(assertion);
            ValidateConditions(assertion);
            ValidateStatements(assertion);
        }

        #region ISaml20AssertionValidator Members

        /// <summary>
        /// Null fields are considered to be valid
        /// </summary>
        private static bool ValidateNotBefore(DateTime? notBefore, DateTime now, TimeSpan allowedClockSkew)
        {
            if (notBefore == null)
                return true;

            return TimeRestrictionValidation.NotBeforeValid(notBefore.Value, now, allowedClockSkew);
        }

        /// <summary>
        /// Handle allowed clock skew by increasing notOnOrAfter with allowedClockSkew
        /// </summary>
        private static bool ValidateNotOnOrAfter(DateTime? notOnOrAfter, DateTime now, TimeSpan allowedClockSkew)
        {
            if (notOnOrAfter == null)
                return true;

            return TimeRestrictionValidation.NotOnOrAfterValid(notOnOrAfter.Value, now, allowedClockSkew);
        }

        public void ValidateTimeRestrictions(Assertion assertion, TimeSpan allowedClockSkew, DateTime currentUtcTime)
        {
            // Conditions are not required
            if (assertion.Conditions == null)
                return;

            Conditions conditions = assertion.Conditions;
            // Negative allowed clock skew does not make sense - we are trying to relax the restriction interval, not restrict it any further
            if (allowedClockSkew < TimeSpan.Zero)
                allowedClockSkew = allowedClockSkew.Negate();
            
            // NotBefore must not be in the future
            if (!ValidateNotBefore(conditions.NotBefore, currentUtcTime, allowedClockSkew))
                throw new Saml20FormatException("Conditions.NotBefore is not within expected range");

            // NotOnOrAfter must not be in the past
            if (!ValidateNotOnOrAfter(conditions.NotOnOrAfter, currentUtcTime, allowedClockSkew))
                throw new Saml20FormatException("Conditions.NotOnOrAfter is not within expected range");

            foreach (AuthnStatement statement in assertion.GetAuthnStatements())
            {                
                if (statement.SessionNotOnOrAfter != null
                    && statement.SessionNotOnOrAfter <= currentUtcTime)
                    throw new Saml20FormatException("AuthnStatement attribute SessionNotOnOrAfter is not within expected range");

                // TODO: Consider validating that authnStatement.AuthnInstant is in the past
            }

            if (assertion.Subject != null)
            {
                foreach (object o in assertion.Subject.Items)
                {
                    if (!(o is SubjectConfirmation))
                        continue;

                    SubjectConfirmation subjectConfirmation = (SubjectConfirmation) o;
                    if (subjectConfirmation.SubjectConfirmationData == null)
                        continue;

                    if (!ValidateNotBefore(subjectConfirmation.SubjectConfirmationData.NotBefore, currentUtcTime, allowedClockSkew))
                        throw new Saml20FormatException("SubjectConfirmationData.NotBefore is not within expected range");

                    if (!ValidateNotOnOrAfter(subjectConfirmation.SubjectConfirmationData.NotOnOrAfter, currentUtcTime, allowedClockSkew))
                        throw new Saml20FormatException("SubjectConfirmationData.NotOnOrAfter is not within expected range");
                }
                
            }
        }

        #endregion

        /// <summary>
        /// Validates that all the required attributes are present on the assertion.
        /// Furthermore it validates validity of the Issuer element.
        /// </summary>
        /// <param name="assertion"></param>
        private void ValidateAssertionAttributes(Assertion assertion)
        {
            //There must be a Version
            if (!Saml20Utils.ValidateRequiredString(assertion.Version))
                throw new Saml20FormatException("Assertion element must have the Version attribute set.");

            //Version must be 2.0
            if (assertion.Version != Saml20Constants.Version)
                throw new Saml20FormatException("Wrong value of version attribute on Assertion element");

            //Assertion must have an ID
            if (!Saml20Utils.ValidateRequiredString(assertion.ID))
                throw new Saml20FormatException("Assertion element must have the ID attribute set.");

            // Make sure that the ID elements is at least 128 bits in length (SAML2.0 std section 1.3.4)
            if (!Saml20Utils.ValidateIDString(assertion.ID))
                throw new Saml20FormatException("Assertion element must have an ID attribute with at least 16 characters (the equivalent of 128 bits)");

            //IssueInstant must be set.
            if (!assertion.IssueInstant.HasValue)
                throw new Saml20FormatException("Assertion element must have the IssueInstant attribute set.");

            //There must be an Issuer
            if (assertion.Issuer == null)
                throw new Saml20FormatException("Assertion element must have an issuer element.");

            //The Issuer element must be valid
            NameIDValidator.ValidateNameID(assertion.Issuer);
        }

        /// <summary>
        /// Validates the subject of an Asssertion
        /// </summary>
        /// <param name="assertion"></param>
        private void ValidateSubject(Assertion assertion)
        {
            if (assertion.Subject == null)
            {
                //If there is no statements there must be a subject
                // as specified in [SAML2.0std] section 2.3.3
                if (assertion.Items == null || assertion.Items.Length == 0)
                    throw new Saml20FormatException("Assertion with no Statements must have a subject.");

                foreach (StatementAbstract o in assertion.Items)
                {
                    //If any of the below types are present there must be a subject.
                    if (o is AuthnStatement || o is AuthzDecisionStatement || o is AttributeStatement)
                        throw new Saml20FormatException("AuthnStatement, AuthzDecisionStatement and AttributeStatement require a subject.");
                }
            }
            else
            {
                //If a subject is present, validate it
                SubjectValidator.ValidateSubject(assertion.Subject);
            }
        }

        /// <summary>
        /// Validates the Assertion's conditions 
        /// Audience restrictions processing rules are:
        ///  - Within a single audience restriction condition in the assertion, the service must be configured
        ///    with an audience-list that contains at least one of the restrictions in the assertion ("OR" filter)
        ///  - When multiple audience restrictions are present within the same assertion, all individual audience 
        ///    restriction conditions must be met ("AND" filter)
        /// </summary>
        private void ValidateConditions(Assertion assertion)
        {
            // Conditions are not required
            if (assertion.Conditions == null)
                return;

            bool oneTimeUseSeen = false;
            bool proxyRestrictionsSeen = false;
            
            ValidateConditionsInterval(assertion.Conditions);

            foreach (ConditionAbstract cat in assertion.Conditions.Items)
            {
                if (cat is OneTimeUse)
                {
                    if (oneTimeUseSeen)
                    {
                        throw new Saml20FormatException("Assertion contained more than one condition of type OneTimeUse");
                    }
                    oneTimeUseSeen = true;
                    continue;
                }

                if (cat is ProxyRestriction)
                {
                    if (proxyRestrictionsSeen)
                    {
                        throw new Saml20FormatException("Assertion contained more than one condition of type ProxyRestriction");
                    }
                    proxyRestrictionsSeen = true;

                    ProxyRestriction proxyRestriction = (ProxyRestriction) cat;
                    if (!String.IsNullOrEmpty(proxyRestriction.Count))
                    {
                        uint res;
                        if (!UInt32.TryParse(proxyRestriction.Count, out res))
                            throw new Saml20FormatException("Count attribute of ProxyRestriction MUST BE a non-negative integer");
                    }

                    if (proxyRestriction.Audience != null)
                    {
                        foreach(string audience in proxyRestriction.Audience)
                        {
                            if (!Uri.IsWellFormedUriString(audience, UriKind.Absolute))
                                throw new Saml20FormatException("ProxyRestriction Audience MUST BE a wellformed uri");
                        }
                    }
                }

                // AudienceRestriction processing goes here (section 2.5.1.4 of [SAML2.0std])
                if (cat is AudienceRestriction)
                {
                    // No audience restrictions? No problems...
                    AudienceRestriction audienceRestriction = (AudienceRestriction)cat;
                    if (audienceRestriction.Audience == null || audienceRestriction.Audience.Count == 0)
                        continue;

                    // If there are no allowed audience uris configured for the service, the assertion is not
                    // valid for this service
                    if (_allowedAudienceUris == null || _allowedAudienceUris.Count < 1)
                        throw new Saml20FormatException("The service is not configured to meet any audience restrictions");

                    string match = null;
                    foreach (string audience in audienceRestriction.Audience)
                    {
                        //In QuirksMode this validation is omitted
                        if (!_quirksMode)
                        {
                            // The given audience value MUST BE a valid URI
                            if (!Uri.IsWellFormedUriString(audience, UriKind.Absolute))
                                throw new Saml20FormatException("Audience element has value which is not a wellformed absolute uri");
                        }

                        match =
                            _allowedAudienceUris.Find(
                                delegate(string allowedUri) { return allowedUri.Equals(audience); });
                        if (match != null)
                            break;
                    }

                    if (Trace.ShouldTrace(TraceEventType.Verbose))
                    {
                        string intended = "Intended uris: " + Environment.NewLine + String.Join(Environment.NewLine, audienceRestriction.Audience.ToArray());
                        string allowed = "Allowed uris: " + Environment.NewLine + String.Join(Environment.NewLine, _allowedAudienceUris.ToArray());
                        Trace.TraceData(TraceEventType.Verbose, Trace.CreateTraceString(GetType(), "ValidateConditions"), intended, allowed);
                    }

                    if (match == null)
                        throw new Saml20FormatException("The service is not configured to meet the given audience restrictions");
                }
            }
        }
        
        /// <summary>
        /// If both conditions.NotBefore and conditions.NotOnOrAfter are specified, NotBefore 
        /// MUST BE less than NotOnOrAfter 
        /// </summary>
        /// <exception cref="Saml20FormatException">If <param name="conditions"/>.NotBefore is not less than <paramref name="conditions"/>.NotOnOrAfter</exception>        
        private static void ValidateConditionsInterval(Conditions conditions)
        {
            // No settings? No restrictions
            if (conditions.NotBefore == null && conditions.NotOnOrAfter == null)
                return;
            
            if (conditions.NotBefore != null && conditions.NotOnOrAfter != null && conditions.NotBefore.Value >= conditions.NotOnOrAfter.Value)
                throw new Saml20FormatException(String.Format("NotBefore {0} MUST BE less than NotOnOrAfter {1} on Conditions", Saml20Utils.ToUTCString(conditions.NotBefore.Value), Saml20Utils.ToUTCString(conditions.NotOnOrAfter.Value)));
        }

        /// <summary>
        /// Validates the details of the Statements present in the assertion ([SAML2.0std] section 2.7)
        /// NOTE: the rules relating to the enforcement of a Subject element are handled during Subject validation
        /// </summary>
        private void ValidateStatements(Assertion assertion)
        {
            // Statements are not required
            if (assertion.Items == null)
                return;

            foreach (StatementAbstract o in assertion.Items)
            {
                StatementValidator.ValidateStatement(o);
            }
        }
        #endregion
    }
}