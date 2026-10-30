using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
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
                var found = store.Certificates.Find(x509FindType, findValue, false);
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

        /// <summary>
        /// The certificate to sign with: of the certificates found that have a private key and are within their
        /// validity period, the one with the latest NotBefore. Null if there is none.
        /// </summary>
        public X509Certificate2 GetFirstValidX509Certificate()
        {
            return GetValidCertificates().FirstOrDefault();
        }

        /// <summary>
        /// The certificates found that have a private key and are within their validity period, latest NotBefore first.
        /// Null if there are none.
        /// </summary>
        public X509Certificate2Collection GetAllValidX509Certificates()
        {
            var valid = GetValidCertificates();
            return valid.Length == 0 ? null : new X509Certificate2Collection(valid);
        }

        /// <summary>
        /// How long the certificates found in the store are used before the store is searched again.
        /// </summary>
        internal TimeSpan RefreshInterval = TimeSpan.FromMinutes(10);

        internal Func<X509Certificate2Collection> FindInStore;

        private readonly object _cacheLock = new object();
        private X509Certificate2[] _cached;
        private DateTime _cachedAt;

        private X509Certificate2[] GetValidCertificates()
        {
            var now = DateTime.Now;
            X509Certificate2[] candidates;
            lock (_cacheLock)
            {
                if (_cached == null || now - _cachedAt >= RefreshInterval || now < _cachedAt)
                {
                    candidates = (FindInStore ?? FindAll)()
                        .Cast<X509Certificate2>()
                        .Where(certificate => certificate.HasPrivateKey)
                        .OrderByDescending(certificate => certificate.NotBefore)
                        .ToArray();
                    // Not cached when nothing is found, so a certificate installed afterwards is found on the next call.
                    _cached = candidates.Length == 0 ? null : candidates;
                    _cachedAt = now;
                }
                else
                {
                    candidates = _cached;
                }
            }

            return candidates.Where(certificate => certificate.NotBefore <= now && now <= certificate.NotAfter).ToArray();
        }

        private X509Certificate2Collection FindAll()
        {
            var store = new X509Store(storeName, storeLocation);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                return store.Certificates.Find(x509FindType, findValue, false);
            }
            finally
            {
                store.Close();
            }
        }

        private string SearchDescriptor()
        {
            var msg = $"The certificate was searched for in {storeLocation}/{storeName}, {x509FindType}='{findValue}'.";

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
        /// Ignored. The SP's own certificate is checked for its validity period only; its chain and revocation are
        /// checked by the IdP that trusts it. Kept so that existing configuration files can still be read.
        /// </summary>
        [XmlAttribute]
        public bool validOnly = false;
    }
}