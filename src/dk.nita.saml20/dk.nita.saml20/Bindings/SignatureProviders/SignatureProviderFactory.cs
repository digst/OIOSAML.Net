using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using dk.nita.saml20.config;

namespace dk.nita.saml20.Bindings.SignatureProviders
{
    /// <summary>
    /// Provides concrete instances of <see cref="ISignatureProvider"/>
    /// </summary>
    public class SignatureProviderFactory
    {
        /// <summary>
        /// returns the validated <see cref="config.ShaHashingAlgorithm"/>
        /// </summary>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static ShaHashingAlgorithm ValidateShaHashingAlgorithm(string shaHashingAlgorithm)
        {
            ShaHashingAlgorithm val;
            if (Enum.TryParse(shaHashingAlgorithm, out val) && Enum.IsDefined(typeof(ShaHashingAlgorithm), val))
            {
                return val;
            }

            throw new InvalidOperationException($"The value of the configuration element 'ShaHashingAlgorithm' is not valid: '{shaHashingAlgorithm}'. Value must be either SHA1, SHA256 or SHA512");
        }

        /// <summary>
        /// Returns a signature provider based on a hashing algorithm
        /// </summary>
        /// <param name="signingKeyType"></param>
        /// <param name="algorithmUri"></param>
        /// <returns></returns>
        public static ISignatureProvider CreateFromHashingAlgorithmSignatureUri(Type signingKeyType, string algorithmUri)
        {
            if (signingKeyType == typeof(RSA) || signingKeyType.IsSubclassOf(typeof(RSA)))
            {
                switch (algorithmUri)
                {
                    case SignedXml.XmlDsigRSASHA1Url: return new RsaSha1SignatureProvider();
                    case SignedXml.XmlDsigRSASHA256Url: return new RsaSha256SignatureProvider();
                    case SignedXml.XmlDsigRSASHA512Url: return new RsaSha512SignatureProvider();
                    default: throw new InvalidOperationException($"Unsupported hashing algorithm uri '{algorithmUri}' provided while using RSA signing key");
                }
            }

            if (signingKeyType == typeof(DSA) || signingKeyType.IsSubclassOf(typeof(DSA)))
            {
                return new DsaSha1SignatureProvider();
            }

            throw new InvalidOperationException($"The signing key type {signingKeyType.FullName} is not supported by OIOSAML.NET. It must be either a DSA or RSA key.");
        }

        /// <summary>
        /// Returns a RSA signature provider based on a hashing algorithm.
        /// </summary>
        /// <param name="hashingAlgorithm"></param>
        /// <returns></returns>
        public static ISignatureProvider CreateFromShaHashingAlgorithmName(ShaHashingAlgorithm hashingAlgorithm)
        {
            return CreateFromShaHashingAlgorithmName(typeof(RSA), hashingAlgorithm);
        }

        /// <summary>
        /// Returns a signature provider based on a hashing algorithm
        /// </summary>
        /// <param name="signingKeyType"></param>
        /// <param name="hashingAlgorithm"></param>
        /// <returns></returns>
        public static ISignatureProvider CreateFromShaHashingAlgorithmName(Type signingKeyType, ShaHashingAlgorithm hashingAlgorithm)
        {
            if (signingKeyType == typeof(RSA) || signingKeyType.IsSubclassOf(typeof(RSA)))
            {
                switch (hashingAlgorithm)
                {
                    case ShaHashingAlgorithm.SHA1: return new RsaSha1SignatureProvider();
                    case ShaHashingAlgorithm.SHA256: return new RsaSha256SignatureProvider();
                    case ShaHashingAlgorithm.SHA512: return new RsaSha512SignatureProvider();
                    default: throw new InvalidOperationException($"Unsupported hashing algorithm '{hashingAlgorithm}' provideded while using RSA signing key");
                }
            }

            if (signingKeyType == typeof(DSA) || signingKeyType.IsSubclassOf(typeof(DSA)))
            {
                return new DsaSha1SignatureProvider();
            }

            throw new InvalidOperationException($"The signing key type {signingKeyType.FullName} is not supported by OIOSAML.NET. It must be either a DSA or RSA key.");
        }
    }
}