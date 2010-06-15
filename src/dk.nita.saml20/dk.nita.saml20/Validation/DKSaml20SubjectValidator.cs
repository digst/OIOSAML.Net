using dk.nita.saml20.Profiles.DKSaml20;
using dk.nita.saml20.Schema.Core;

namespace dk.nita.saml20.Validation
{
    internal class DKSaml20SubjectValidator : ISaml20SubjectValidator
    {
        #region Properties

        private ISaml20SubjectConfirmationValidator _subjectConfirmationValidator;

        private ISaml20SubjectConfirmationValidator SubjectConfirmationValidator
        {
            get
            {
                if (_subjectConfirmationValidator == null)
                    _subjectConfirmationValidator = new DKSaml20SubjectConfirmationValidator();
                return _subjectConfirmationValidator;
            }
        }

        #endregion

        public void ValidateSubject(Subject subject)
        {
            if (subject.Items == null || subject.Items.Length == 0)
                throw new DKSaml20FormatException("The DK-SAML 2.0 Profile requires at least one \"SubjectConfirmation\" element within the \"Subject\" element.");

            bool subjectConfirmationPresent = false;
            foreach (object item in subject.Items)
            {
                if (item is SubjectConfirmation)
                {
                    SubjectConfirmation subjectConfirmation = (SubjectConfirmation)item;
                    if (subjectConfirmation.Method == SubjectConfirmation.BEARER_METHOD)
                        subjectConfirmationPresent = true;

                    SubjectConfirmationValidator.ValidateSubjectConfirmation(subjectConfirmation);
                }
            }
            if (!subjectConfirmationPresent)
                throw new DKSaml20FormatException("The DK-SAML 2.0 Profile requires that a bearer \"SubjectConfirmation\" element is present.");
        }
    }
}