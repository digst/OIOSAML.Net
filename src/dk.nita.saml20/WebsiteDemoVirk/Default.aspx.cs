using System;
using System.Configuration;
using System.Web.UI;
using dk.nita.saml20.config;

namespace WebsiteDemo
{
    public partial class _Default : Page
    {
        /// <summary>
        /// Indicates whether the certificate is incorrectly configured in web.config.
        /// </summary>
        protected bool certificateMissing;

        protected void Page_Load(object sender, EventArgs e)
        {
            try
            {
                FederationConfig.GetConfig().SigningCertificate.GetCertificate();
                certificateMissing = false; // GetCertificate() throws an exception when the certificate can not be retrieved.
            } catch(ConfigurationErrorsException)
            {
                certificateMissing = true;
            }
        }
    }
}
