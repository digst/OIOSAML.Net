using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using dk.nita.saml20.config;
using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.Schema.Protocol;
using dk.nita.saml20.Utils;
using dk.nita.saml20.Validation;

namespace dk.nita.saml20
{
    ///<summary>
    /// Encapsulates the functionality required of a DK-SAML 2.0 Assertion. 
    /// 
    ///</summary>
    public class Saml20Assertion 
    {
        #region Private variables
        /// <summary>
        /// The primary storage of the assertion. When deserialized or signed, the token will be stored in this field.
        /// </summary>
        private XmlElement _samlAssertion;

        /// <summary>
        /// A strongly-typed version of the assertion. It is generated on-demand from the contents of the <code>_samlAssertion</code>
        /// field. 
        /// </summary>
        private Assertion _assertion;

        private ISaml20AssertionValidator _assertionValidator;

        private AssertionProfile profile;

        private int _allowedClockSkewMinutes;

        /// <summary>
        /// An list of the unencrypted attributes in the assertion. This list is lazy initialized, ie. it will only be retrieved
        /// from the <code>_samlAssertion</code> field when it is requested through the <code>Attributes</code> property.
        /// 
        /// When the <code>Sign</code> method is called, the attributes in the list are embedded into the <code>_samlAssertion</code>
        /// and this variable is nulled.
        /// </summary>
        private List<SamlAttribute> _assertionAttributes;

        private List<EncryptedElement> _encryptedAssertionAttributes;

        private string _encryptedId;

        private AsymmetricAlgorithm _signingKey;

        private bool _quirksMode = false;

        #endregion

        #region Properties

        private ISaml20AssertionValidator AssertionValidator
        {
            get
            {
                if (_assertionValidator == null)
                {
                    FederationConfig config = FederationConfig.GetConfig();
                    _allowedClockSkewMinutes = config.AllowedClockSkewMinutes;

                    if (config == null || config.AllowedAudienceUris == null)
                    {
                        if (profile == AssertionProfile.DKSaml)
                            _assertionValidator = new DKSaml20AssertionValidator(null, _quirksMode);
                        else
                            _assertionValidator = new Saml20AssertionValidator(null, _quirksMode);
                    }
                    else
                    {
                        if (profile == AssertionProfile.DKSaml)
                            _assertionValidator = new DKSaml20AssertionValidator(config.AllowedAudienceUris.Audiences, _quirksMode);
                        else
                            _assertionValidator = new Saml20AssertionValidator(config.AllowedAudienceUris.Audiences, _quirksMode);
                    }
                }
                return _assertionValidator;
            }
        }

        /// <summary>
        /// A strongly-typed version of the Saml Assertion. It is lazily generated based on the contents of the
        /// <code>_samlAssertion</code> field.
        /// </summary>
        public Assertion Assertion
        {
            get
            {
                if(_assertion == null)
                {
                    if (_samlAssertion == null)
                        throw new InvalidOperationException("No assertion is loaded.");

                    XmlNodeReader reader = new XmlNodeReader(_samlAssertion);
                    _assertion = Serialization.Deserialize<Assertion>(reader);
                }
                    
                return _assertion;
            }
        }

        /// <summary>
        /// Gets the assertion in XmlElement representation.
        /// </summary>
        /// <value>The XML assertion.</value>
        public XmlElement XmlAssertion
        {
            get
            {
                return _samlAssertion;
            }
        }

        /// <summary>
        /// Gets the subject.
        /// </summary>
        /// <value>The subject.</value>
        public NameID Subject
        {
            get
            {
                foreach (object o in Assertion.Subject.Items)
                {
                    if(o is NameID)
                        return (NameID) o;
                }
                return null;
            }
        }

        /// <summary>
        /// Gets the subject items.
        /// </summary>
        /// <value>The subject items.</value>
        public object[] SubjectItems
        {
            get
            {
                return Assertion.Subject.Items;
            }
        }

        /// <summary>
        /// They asymmetric key that can verify the signature of the assertion.
        /// </summary>
        public AsymmetricAlgorithm SigningKey
        {
            get { return _signingKey; }
            set { _signingKey = value; }
        }

        /// <summary>
        /// Retrieve the value of the &lt;Issuer&gt; element.
        /// </summary>
        public string Issuer
        {
            get { return Assertion.Issuer.Value; }
        }

        /// <summary>
        /// The ID attribute of the &lt;Assertion&gt; element.
        /// </summary>
        public string Id
        {
            get { return Assertion.ID; }
        }

        /// <summary>
        /// Gets the SessionIndex of the AuthnStatement
        /// </summary>
        public string SessionIndex
        {
            get
            {
                List<AuthnStatement> list = Assertion.GetAuthnStatements();
                if (list.Count > 0)
                {
                    return list[0].SessionIndex;
                }

                return string.Empty;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the assertion has a OneTimeUse condition.
        /// </summary>
        /// <value>
        /// 	<c>true</c> if the assertion has a OneTimeUse condition; otherwise, <c>false</c>.
        /// </value>
        public bool IsOneTimeUse
        {
            get
            {
                foreach (ConditionAbstract item in Assertion.Conditions.Items)
                {
                    if(item is OneTimeUse)
                        return true;
                }

                return false;
            }
        }

        /// <summary>
        /// The unencrypted attributes of the assertion.
        /// </summary>
        public List<SamlAttribute> Attributes
        {
            get
            {
                if (_assertionAttributes == null)
                    ExtractAttributes(); // Lazy initialization of the attributes list.                
                return _assertionAttributes;
            }
            set
            {
                // _assertionAttributes == null is reserved for signalling that the attribute is not initialized, so 
                // convert it to an empty list.
                if (value == null) 
                    value = new List<SamlAttribute>(0);
                _assertionAttributes = value;
            }
        }

        /// <summary>
        /// The encrypted attributes of the assertion.
        /// </summary>
        public List<EncryptedElement> EncryptedAttributes
        {
            get 
            { 
                if (_encryptedAssertionAttributes == null)
                    ExtractAttributes(); // Lazy initialization of the attributes list.
                return _encryptedAssertionAttributes;
            }

            set
            {
                // _encryptedAssertionAttributes == null is reserved for signalling that the attribute is not initialized, so 
                // convert it to an empty list.
                if (value == null)
                    value = new List<EncryptedElement>(0);

                _encryptedAssertionAttributes = value;
            }
        }

        /// <summary>
        /// Gets or sets the encrypted id.
        /// </summary>
        /// <value>The encrypted id.</value>
        public string EncryptedId
        {
            get { return _encryptedId; }
            set { _encryptedId = value; }
        }

        /// <summary>
        /// Retrieve the NotOnOrAfter propoerty, if it is included in the assertion.
        /// </summary>
        public DateTime NotOnOrAfter
        {
            get
            {
                // Find the SubjectConfirmation element for the ValidTo attribute. [DKSAML] ch. 7.1.4.
                foreach (object o in Assertion.Subject.Items)
                {
                    if (o is SubjectConfirmation)
                    {
                        SubjectConfirmation subjectConfirmation = (SubjectConfirmation)o;
                        if (subjectConfirmation.SubjectConfirmationData.NotOnOrAfter.HasValue)
                            return subjectConfirmation.SubjectConfirmationData.NotOnOrAfter.Value;
                    }
                }

                return DateTime.MaxValue;
            }
        }

        /// <summary>
        /// Gets the conditions element of the assertion.
        /// </summary>
        /// <value>The conditions element.</value>
        public Conditions Conditions
        {
            get
            {
                return _assertion.Conditions;
            }
        }

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20Assertion"/> class.
        /// </summary>
        public Saml20Assertion() 
        {}

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20Assertion"/> class.
        /// </summary>
        /// <param name="assertion">The assertion.</param>
        /// <param name="trustedSigners">If <code>null</code>, the signature of the given assertion is not verified.</param>
        /// <param name="quirksMode">if set to <c>true</c> quirks mode is enabled.</param>
        public Saml20Assertion(XmlElement assertion, IEnumerable<AsymmetricAlgorithm> trustedSigners, bool quirksMode)
        {
            _quirksMode = quirksMode;
            profile = AssertionProfile.DKSaml;
            LoadXml(assertion, trustedSigners);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20Assertion"/> class.
        /// </summary>
        /// <param name="assertion">The assertion.</param>
        /// <param name="trustedSigners">If <code>null</code>, the signature of the given assertion is not verified.</param>
        /// <param name="profile">Determines the type of validation to perform on the token</param>
        /// <param name="quirksMode">if set to <c>true</c> quirks mode is enabled.</param>
        public Saml20Assertion(XmlElement assertion, IEnumerable<AsymmetricAlgorithm> trustedSigners, AssertionProfile profile, bool quirksMode){
            this.profile = profile;
            _quirksMode = quirksMode;
            LoadXml(assertion, trustedSigners);
        }

        #endregion

        /// <summary>
        /// Check the signature of the XmlDocument using the list of keys. 
        /// If the signature key is found, the SigningKey property is set.
        /// </summary>
        /// <param name="keys">A list of KeyDescriptor elements. Probably extracted from the metadata describing the IDP that sent the message.</param>
        /// <returns>True, if one of the given keys was able to verify the signature. False in all other cases.</returns>
        public bool CheckSignature(IEnumerable<AsymmetricAlgorithm> keys)
        {
            if (keys == null)
                throw new ArgumentNullException("keys");

            foreach (AsymmetricAlgorithm key in keys)
            {
                if (key == null)
                    continue;

                if (CheckSignature(key)) 
                    return true;
            }

            return false;
        }

        private bool CheckSignature(AsymmetricAlgorithm key)
        {
            if (XmlSignatureUtils.CheckSignature(_samlAssertion, key))
            {
                SigningKey = key;
                return true;
            }
            return false;
            
        }

        /// <summary>
        /// Verifies the assertion's signature and its time to live.
        /// </summary>
        /// <exception cref="Saml20Exception">if the assertion's signature can not be verified or its time to live has been exceeded.</exception>
        public void CheckValid(IEnumerable<AsymmetricAlgorithm> trustedSigners)
        {
            if (!CheckSignature(trustedSigners))
                throw new Saml20Exception("Signature could not be verified.");

            if (IsExpired())
                throw new Saml20Exception("Assertion is no longer valid.");
        }
        
        /// <summary>
        /// Checks if the expiration time has been exceeded.
        /// </summary>        
        public bool IsExpired()
        {
            return DateTime.UtcNow > NotOnOrAfter.AddMinutes(_allowedClockSkewMinutes);
        }

        /// <summary>
        /// Returns the KeyInfo element of the signature of the token.
        /// </summary>
        /// <returns>Null if the token is not signed. The KeyInfo element otherwise.</returns>
        public KeyInfo GetSignatureKeys()
        {
            if (!XmlSignatureUtils.IsSigned(_samlAssertion))
                return null;

            return XmlSignatureUtils.ExtractSignatureKeys(_samlAssertion);
            
            
        }

        /// <summary>
        /// Returns the SubjectConfirmationData from the assertion subject items
        /// </summary>
        /// <returns>SubjectConfirmationData object from subject items, null if none present</returns>
        public SubjectConfirmationData GetSubjectConfirmationData()
        {
            foreach (var item in SubjectItems)
            {
                if (item is SubjectConfirmation)
                    return ((SubjectConfirmation)item).SubjectConfirmationData;
            }
            return null;
        }

        /// <summary>
        /// Gets the assertion as an XmlDocument.
        /// </summary>
        /// <returns></returns>
        public XmlElement GetXml()
        {
            return _samlAssertion;
        }

        /// <summary>
        /// Extracts the list of attributes from the &lt;AttributeStatement&gt; of the assertion, and 
        /// stores it in <code>_assertionAttributes</code>.
        /// </summary>
        private void ExtractAttributes()
        {            
            _assertionAttributes = new List<SamlAttribute>(0);
            _encryptedAssertionAttributes = new List<EncryptedElement>(0);

            XmlNodeList list =
                _samlAssertion.GetElementsByTagName(AttributeStatement.ELEMENT_NAME, Saml20Constants.ASSERTION);

            if (list.Count == 0)
                return;

            // NOTE It would be nice to implement a better-performing solution where only the AttributeStatement is converted.
            // NOTE Namespace issues in the xml-schema "type"-attribute prevents this, though.
            Assertion assertion = Serialization.Deserialize<Assertion>(new XmlNodeReader(_samlAssertion));
                        
            List<AttributeStatement> attributeStatements = assertion.GetAttributeStatements();
            if (attributeStatements.Count == 0 || attributeStatements[0].Items == null)
                return;

            AttributeStatement attributeStatement = attributeStatements[0];            
            foreach (object item in attributeStatement.Items)
            {
                if (item is SamlAttribute)
                    _assertionAttributes.Add((SamlAttribute)item);

                if (item is EncryptedElement)
                    _encryptedAssertionAttributes.Add((EncryptedElement) item);
            }
        }

        /// <summary>
        /// Loads an assertion from XML.
        /// </summary>
        /// <param name="element">The element.</param>
        /// <param name="trustedSigners">The trusted signers.</param>
        private void LoadXml(XmlElement element, IEnumerable<AsymmetricAlgorithm> trustedSigners)
        {
            _samlAssertion = element;
            if (trustedSigners != null)
                if (!CheckSignature(trustedSigners))
                    throw new Saml20Exception("Assertion signature could not be verified.");
        }

        /// <summary>
        /// Validates the assertion
        /// </summary>
        /// <param name="currentUtcTime"></param>
        public void Validate(DateTime currentUtcTime)
        {
            // Validate the saml20Assertion.      
            AssertionValidator.ValidateAssertion(Assertion);
            AssertionValidator.ValidateTimeRestrictions(Assertion, TimeSpan.FromMinutes(_allowedClockSkewMinutes), currentUtcTime);
        }

        /// <summary>
        /// Writes the token to a writer.
        /// </summary>
        /// <param name="writer">The writer.</param>
        public void WriteAssertion(XmlWriter writer)
        {
            _samlAssertion.WriteTo(writer);
        }
    }

    /// <summary>
    /// Assertion validation profiles
    /// </summary>
    public enum AssertionProfile
    {
        /// <summary>
        /// Validate assertion core profile
        /// </summary>
        Core,
        /// <summary>
        /// Valiadate DKSaml profile (including core)
        /// </summary>
        DKSaml,
    }
}