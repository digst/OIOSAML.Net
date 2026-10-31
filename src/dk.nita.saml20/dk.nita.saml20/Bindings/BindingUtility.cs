using System;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using dk.nita.saml20.config;
using dk.nita.saml20.Properties;

namespace dk.nita.saml20.Bindings
{
    /// <summary>
    /// Utility functions for use in binding implementations.
    /// </summary>
    public class BindingUtility
    {
        /// <summary>
        /// Validates the SAML20Federation configuration.
        /// </summary>
        /// <param name="errorMessage">The error message. If validation passes, it will be an empty string. Otherwise it will contain a userfriendly message.</param>
        /// <returns>True if validation passes, false otherwise</returns>
        public static bool ValidateConfiguration(out string errorMessage)
        {
            SAML20FederationConfig _config;

            try
            {
                _config = SAML20FederationConfig.GetConfig();
                if (_config == null)
                {
                    errorMessage = Saml20Resources.MissingSaml20Federation;
                    return false;
                }
                if (_config.ServiceProvider == null)
                {
                    errorMessage =
                        Saml20Resources.MissingServiceProvider;
                    return false;
                }
                if (string.IsNullOrEmpty(_config.ServiceProvider.ID))
                {
                    errorMessage =
                        Saml20Resources.MissingServiceProviderId;
                    return false;
                }
                if (!Uri.TryCreate(_config.ServiceProvider.Server, UriKind.Absolute, out _))
                {
                    errorMessage =
                        Saml20Resources.MissingServiceProviderServer;
                    return false;
                }
                if (FederationConfig.GetConfig().SigningCertificates == null || FederationConfig.GetConfig().SigningCertificates.Count == 0)
                {
                    errorMessage = Saml20Resources.MissingSigningCertificate;
                    return false;
                }
                try
                {
                    foreach (Certificate certificate in FederationConfig.GetConfig().SigningCertificates)
                    {
                        X509Certificate2 signingCert = certificate.GetCertificate();
                        if (!signingCert.HasPrivateKey)
                        {
                            errorMessage = Saml20Resources.SigningCertificateMissingPrivateKey;
                            return false;
                        }
                    }
                }
                catch (Exception ex)
                {
                    errorMessage = Saml20Resources.SigningCertficateLoadError + ex.Message;
                    return false;
                }

                if (_config.IDPEndPoints == null)
                {
                    errorMessage = Saml20Resources.MissingIDPEndpoints;
                    return false;
                }

                if (_config.Endpoints.MetadataLocation == null)
                {
                    errorMessage = Saml20Resources.MissingMetadataLocation;
                    return false;
                }

            }
            catch (Exception ex)
            {
                errorMessage = ex.ToString();
                return false;
            }

            errorMessage = string.Empty;
            return true;
        }
    }
}