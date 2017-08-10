using System;
using System.Diagnostics;
using System.IdentityModel.Selectors;
using System.Security.Cryptography.X509Certificates;
using dk.nita.saml20.Properties;
using Trace=dk.nita.saml20.Utils.Trace;

namespace dk.nita.saml20.Specification
{
    /// <summary>
    /// Checks if a certificate is within its validity period
    /// Performs an online revocation check if the certificate contains a CRL url (oid: 2.5.29.31)
    /// </summary>
    public class DefaultCertificateSpecification : ICertificateSpecification
    {
        /// <summary>
        /// Determines whether the specified certificate is considered valid according to the RFC3280 specification.
        /// 
        /// </summary>
        /// <param name="certificate">The certificate to validate.</param>
        /// <param name="failureReason">If the process fails, the reason is outputted in this variable</param>
        /// <returns>
        /// 	<c>true</c> if valid; otherwise, <c>false</c>.
        /// </returns>
        public bool IsSatisfiedBy(X509Certificate2 certificate, out string failureReason)
        {
            bool useMachineContext = false;
            X509ChainPolicy chainPolicy = new X509ChainPolicy();
            chainPolicy.RevocationMode = X509RevocationMode.Online;
            X509CertificateValidator defaultCertificateValidator = X509CertificateValidator.CreateChainTrustValidator(useMachineContext, chainPolicy);

            try
            {
                defaultCertificateValidator.Validate(certificate);
                failureReason = null;
                return true;
            }catch(Exception e)
            {
                failureReason = $"Validating chain with online revocation check failed for certificate '{certificate.Thumbprint}': {e}";
                Trace.TraceData(TraceEventType.Warning, string.Format(Tracing.CertificateIsNotRFC3280Valid, certificate.SubjectName.Name, certificate.Thumbprint, e));
            }

            return false;
        }
    }
}
