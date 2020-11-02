using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.Schema.Protocol;
using dk.nita.saml20.Utils;
using SfwEncryptedData = dk.nita.saml20.Schema.XEnc.EncryptedData;

namespace dk.nita.saml20
{
    /// <summary>
    /// Handles the <code>EncryptedAssertion</code> element. 
    /// </summary>
    public class Saml20AssertionEncryptionUtility
    {
        /// <summary>
        /// Whether to use OAEP (Optimal Asymmetric Encryption Padding) by default, if no EncryptionMethod is specified 
        /// on the &lt;EncryptedKey&gt; element.
        /// </summary>
        private const bool USE_OAEP_DEFAULT = false;

        /// <summary>
        /// The assertion that is stored within the encrypted assertion.
        /// </summary>
        private XmlDocument _assertion;

        /// <summary>
        /// The assertion that is stored within the encrypted assertion.
        /// </summary>
        private XmlDocument _encryptedAssertion;

        /// <summary>
        /// The <code>Assertion</code> element that is embedded within the <code>EncryptedAssertion</code> element.
        /// </summary>
        public XmlDocument EncryptedAssertion
        {
            get { return _encryptedAssertion; }
        }

        /// <summary>
        /// The <code>Assertion</code> element that is embedded within the <code>EncryptedAssertion</code> element.
        /// </summary>
        public XmlDocument Assertion
        {
            get { return _assertion; }
            private set { _assertion = value; }
        }

          /// <summary>
        /// Initializes a new instance of <code>EncryptedAssertion</code>.
        /// </summary>
        public Saml20AssertionEncryptionUtility()
        { }

        /// <summary>
        /// Initializes a new instance of <code>EncryptedAssertion</code>.
        /// </summary>
        /// <param name="transportKey">The transport key is used for securing the symmetric key that has encrypted the assertion.</param>        
        public Saml20AssertionEncryptionUtility(RSA transportKey) : this()
        {
            _transportKey = transportKey;
        }

        /// <summary>
        /// Initializes a new instance of <code>EncryptedAssertion</code>.
        /// </summary>
        /// <param name="transportKey">The transport key is used for securing the symmetric key that has encrypted the assertion.</param>
        /// <param name="encryptedAssertion">An <code>XmlDocument</code> containing an <code>EncryptedAssertion</code> element.</param>
        public Saml20AssertionEncryptionUtility(RSA transportKey, Assertion encryptedAssertion) : this(transportKey)
        {
            var xml = Serialization.SerializeToXmlString(encryptedAssertion);
            var xmlDoc = Serialization.DeserializeFromXmlString<XmlElement>(xml);
            LoadXml(xmlDoc);
        }

        /// <summary>
        /// Initializes the instance with a new <code>EncryptedAssertion</code> element.
        /// </summary>
        public void LoadXml(XmlElement element)
        {
            _assertion = new XmlDocument();
            _assertion.XmlResolver = null;
            _assertion.AppendChild(_assertion.ImportNode(element, true));
        }






        private string _sessionKeyAlgorithm = EncryptedXml.XmlEncAES256Url;

     

        private RSA _transportKey;
        /// <summary>
        /// The transport key is used for securing the symmetric key that has encrypted the assertion.
        /// </summary>
        public RSA TransportKey
        {
            set { _transportKey = value; }
            get { return _transportKey; }
        }

        /// <summary>
        /// Encrypts the Assertion in the assertion property and creates an <code>EncryptedAssertion</code> element
        /// that can be retrieved using the <code>GetXml</code> method.
        /// </summary>
        public void Encrypt()
        {
            if (_transportKey == null)
                throw new InvalidOperationException("The \"TransportKey\" property is required to encrypt the assertion.");

            if (_assertion == null)
                throw new InvalidOperationException("The \"Assertion\" property is required for this operation.");

            EncryptedData encryptedData = new EncryptedData();
            encryptedData.Type = EncryptedXml.XmlEncElementUrl;

            encryptedData.EncryptionMethod = new EncryptionMethod(_sessionKeyAlgorithm);

            // Encrypt the assertion and add it to the encryptedData instance.
            EncryptedXml encryptedXml = new EncryptedXml();
            byte[] encryptedElement = encryptedXml.EncryptData(_assertion.DocumentElement, SessionKey, false);
            encryptedData.CipherData.CipherValue = encryptedElement;

            // Add an encrypted version of the key used.
            encryptedData.KeyInfo = new KeyInfo();

            EncryptedKey encryptedKey = new EncryptedKey();
            encryptedKey.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url);
            encryptedKey.CipherData = new CipherData(EncryptedXml.EncryptKey(SessionKey.Key, TransportKey, false));
            encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));

            // Create an empty EncryptedAssertion to hook into.
           var encryptedAssertion = new EncryptedAssertion();
            encryptedAssertion.encryptedData = new SfwEncryptedData();

            XmlDocument result = new XmlDocument();
            result.XmlResolver = null;
            result.LoadXml(Serialization.SerializeToXmlString(encryptedAssertion));




            XmlElement encryptedDataElement = GetElement(SfwEncryptedData.ELEMENT_NAME, Saml20Constants.XENC, result.DocumentElement);
            EncryptedXml.ReplaceElement(encryptedDataElement, encryptedData, false);

            _encryptedAssertion = result;
        }



 
        /// <summary>
        /// Creates an instance of a symmetric key, based on the algorithm identifier found in the Xml Encryption standard.        
        /// see also http://www.w3.org/TR/xmlenc-core/#sec-Algorithms
        /// </summary>
        /// <param name="algorithm">A string containing one of the algorithm identifiers found in the XML Encryption standard. The class
        /// <code>EncryptedXml</code> contains the identifiers as fields.</param>        
        private static SymmetricAlgorithm GetKeyInstance(string algorithm)
        {
            SymmetricAlgorithm result;
            switch (algorithm)
            {
                case EncryptedXml.XmlEncTripleDESUrl:
                    result = TripleDES.Create();
                    break;
                case EncryptedXml.XmlEncAES128Url:
                    result = new RijndaelManaged();
                    result.KeySize = 128;
                    break;
                case EncryptedXml.XmlEncAES192Url:
                    result = new RijndaelManaged();
                    result.KeySize = 192;
                    break;
                case EncryptedXml.XmlEncAES256Url:
                    result = new RijndaelManaged();
                    result.KeySize = 256;
                    break;
                default:
                    result = new RijndaelManaged();
                    result.KeySize = 256;
                    break;
            }
            return result;
        }


        /// <summary>
        /// Utility method for retrieving a single element from a document.
        /// </summary>
        private static XmlElement GetElement(string element, string elementNS, XmlElement doc)
        {
            XmlNodeList list = doc.GetElementsByTagName(element, elementNS);
            if (list.Count == 0)
                return null;

            return (XmlElement)list[0];
        }


        private SymmetricAlgorithm _sessionKey;

        /// <summary>
        /// The key used for encrypting the <code>Assertion</code>. This key is embedded within a <code>KeyInfo</code> element
        /// in the <code>EncryptedAssertion</code> element. The session key is encrypted with the <code>TransportKey</code> before
        /// being embedded.
        /// </summary>
        private SymmetricAlgorithm SessionKey
        {
            get
            {
                if (_sessionKey == null)
                {
                    _sessionKey = GetKeyInstance(_sessionKeyAlgorithm);
                    _sessionKey.GenerateKey();
                }
                return _sessionKey;
            }
        }

    
    }
}
