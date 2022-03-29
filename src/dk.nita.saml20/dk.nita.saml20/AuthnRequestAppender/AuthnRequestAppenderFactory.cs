using System;
using dk.nita.saml20.config;

namespace dk.nita.saml20.AuthnRequestAppender
{
    /// <summary>
    /// IAuthnRequestAppender Factory
    /// </summary>
    public static class AuthnRequestAppenderFactory
    {
        /// <summary>
        /// Get appender if configured
        /// </summary>
        /// <returns></returns>
        public static IAuthnRequestAppender GetAppender()
        {
            var config = FederationConfig.GetConfig();
            if (string.IsNullOrEmpty(config.AuthnRequestAppender?.type))
            {
                return null;
            }
            return (IAuthnRequestAppender)Activator.CreateInstance(Type.GetType(config.AuthnRequestAppender.type));
        } 
    }
}