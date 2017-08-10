using System.Configuration;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Serialization;
using Saml2.Properties;

namespace dk.nita.saml20.config
{
    /// <summary>
    /// Common implementation of X509 certificate references used in configuration files. 
    /// Specializations are free to provide the xml namespace that fit the best (ie the namespace of the containing element)
    /// </summary>
    public class Certificate
    {
        /// <summary>
        /// Opens the certificate from its store.
        /// </summary>
        /// <returns></returns>
        public X509Certificate2 GetCertificate()
        {            
            var store = new X509Store( storeName, storeLocation);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                var found = store.Certificates.Find(x509FindType, findValue, validOnly);
                if (found.Count == 0)
                {
                    var msg = $"A configured certificate could not be found in the certificate store. {SearchDescriptor()}";
                    throw new ConfigurationErrorsException(msg);
                }
                if (found.Count > 1)
                {
                    var msg = $"Found more than one certificate in the certificate store. Make sure you don't have duplicate certificates installed. {SearchDescriptor()}";
                    throw new ConfigurationErrorsException(msg);
                }
                return found[0];
            }
            finally
            {
                store.Close();
            }
        }

        private string SearchDescriptor()
        {
            var msg = $"The certificate was searched for in {storeLocation}/{storeName}, {x509FindType}='{findValue}', validOnly={validOnly}.";

            if (x509FindType == X509FindType.FindByThumbprint && findValue?.Length > 0 && findValue[0] == 0x200E)
            {
                msg = "\nThe configuration for the certificate searches by thumbprint but has an invalid character in the thumbprint string. Make sure you remove the first hidden character in the thumbprint value in the configuration. See https://support.microsoft.com/en-us/help/2023835/certificate-thumbprint-displayed-in-mmc-certificate-snap-in-has-extra-invisible-unicode-character. \n" + msg;
            }

            return msg;
        }

        /// <summary>
        /// Find value
        /// </summary>
        [XmlAttribute]
        public string findValue;

        /// <summary>
        /// Store location
        /// </summary>
        [XmlAttribute]
        public StoreLocation storeLocation;

        /// <summary>
        /// Store name
        /// </summary>
        [XmlAttribute]
        public StoreName storeName;

        /// <summary>
        /// find type
        /// </summary>
        [XmlAttribute]
        public X509FindType x509FindType;

        /// <summary>
        /// Determines if only valid certificates are found
        /// </summary>
        [XmlAttribute]
        public bool validOnly = false;
    }
}