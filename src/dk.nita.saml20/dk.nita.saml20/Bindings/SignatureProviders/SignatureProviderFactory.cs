using System;
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
            if (Enum.TryParse(shaHashingAlgorithm, out val) && Enum.IsDefined(typeof(ShaHashingAlgorithm), val) && val != ShaHashingAlgorithm.SHA1)
            {
                return val;
            }

            throw new InvalidOperationException($"The value of the configuration element 'ShaHashingAlgorithm' is not valid: '{shaHashingAlgorithm}'. Value must be either SHA256 or SHA512");
        }

        /// <summary>
        /// Returns a signature provider based on a hashing algorithm
        /// </summary>
        /// <param name="algorithmUri"></param>
        /// <returns></returns>
        public static ISignatureProvider CreateFromHashingAlgorithmSignatureUri(string algorithmUri)
        {
            switch (algorithmUri)
            {
                case SignedXml.XmlDsigRSASHA1Url:
                    throw new InvalidOperationException("Signatures with RSA-SHA1 are not accepted [OIO-ALG-01]");
                case SignedXml.XmlDsigRSASHA256Url: return CreateFromShaHashingAlgorithmName(ShaHashingAlgorithm.SHA256);
                case SignedXml.XmlDsigRSASHA512Url: return CreateFromShaHashingAlgorithmName(ShaHashingAlgorithm.SHA512);
                default:
                    throw new InvalidOperationException(
                        $"Unsupported hashing algorithm uri '{algorithmUri}' provided while using RSA signing key");
            }
        }

        /// <summary>
        /// Returns a signature provider based on a hashing algorithm
        /// </summary>
        /// <param name="hashingAlgorithm"></param>
        /// <returns></returns>
        public static ISignatureProvider CreateFromShaHashingAlgorithmName(ShaHashingAlgorithm hashingAlgorithm)
        {
            switch (hashingAlgorithm)
            {
                case ShaHashingAlgorithm.SHA1:
                    throw new InvalidOperationException("Signing with SHA-1 is not allowed [OIO-ALG-01]. Use SHA256 or SHA512.");
                case ShaHashingAlgorithm.SHA256: return new RsaSha256SignatureProvider();
                case ShaHashingAlgorithm.SHA512: return new RsaSha512SignatureProvider();
                default:
                    throw new InvalidOperationException(
                        $"Unsupported hashing algorithm '{hashingAlgorithm}' provideded while using RSA signing key");
            }
        }
    }
}