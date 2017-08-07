using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using dk.nita.saml20.config;

namespace dk.nita.saml20.Bindings.SignatureProviders
{
    internal class SignatureProviderFactory
    {
        /// <summary>
        /// returns the validated <see cref="config.ShaHashingAlgorithm"/>
        /// </summary>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static ShaHashingAlgorithm ValidateShaHashingAlgorithm(string shaHashingAlgorithm)
        {
            if (string.IsNullOrEmpty(shaHashingAlgorithm))
            {
                return ShaHashingAlgorithm.SHA256;
            }

            ShaHashingAlgorithm val;
            if (Enum.TryParse(shaHashingAlgorithm, out val) && Enum.IsDefined(typeof(ShaHashingAlgorithm), val))
            {
                return val;
            }

            throw new InvalidOperationException($"The value of the configuration element 'ShaHashingAlgorithm' is not valid: '{shaHashingAlgorithm}'. Value must be either SHA1, SHA256 or SHA512");
        }

        public static ISignatureProvider CreateFromAlgorithmUri(Type signingKeyType, string algorithmUri)
        {
            if (signingKeyType.IsSubclassOf(typeof(RSA)))
            {
                switch (algorithmUri)
                {
                    case SignedXml.XmlDsigRSASHA1Url: return new RsaSha1SignatureProvider();
                    case Saml20Constants.XmlDsigRSASHA256Url: return new RsaSha256SignatureProvider();
                    case Saml20Constants.XmlDsigRSASHA512Url: return new RsaSha512SignatureProvider();
                    default: throw new InvalidOperationException($"Unsupported hashing algorithm uri '{algorithmUri}' provided while using RSA signing key");
                }
            }

            if (signingKeyType.IsSubclassOf(typeof(DSA)))
            {
                return new DsaSha1SignatureProvider();
            }

            throw new InvalidOperationException($"The signing key type {signingKeyType.FullName} is not supported by OIOSAML.NET. It must be either a DSA or RSA key.");
        }

        public static ISignatureProvider CreateFromAlgorithmName(Type signingKeyType, ShaHashingAlgorithm hashingAlgorithm)
        {
            if (signingKeyType.IsSubclassOf(typeof(RSA)))
            {
                switch (hashingAlgorithm)
                {
                    case ShaHashingAlgorithm.SHA1: return new RsaSha1SignatureProvider();
                    case ShaHashingAlgorithm.SHA256: return new RsaSha256SignatureProvider();
                    case ShaHashingAlgorithm.SHA512: return new RsaSha512SignatureProvider();
                    default: throw new InvalidOperationException($"Unsupported hashing algorithm '{hashingAlgorithm}' provideded while using RSA signing key");
                }
            }

            if (signingKeyType.IsSubclassOf(typeof(DSA)))
            {
                return new DsaSha1SignatureProvider();
            }

            throw new InvalidOperationException($"The signing key type {signingKeyType.FullName} is not supported by OIOSAML.NET. It must be either a DSA or RSA key.");
        }
    }
}