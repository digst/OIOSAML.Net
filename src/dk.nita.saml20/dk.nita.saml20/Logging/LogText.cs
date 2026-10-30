using System;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using dk.nita.saml20.Utils;

namespace dk.nita.saml20.Logging
{
    /// <summary>
    /// Turns SAML messages and other values into text that is safe to log.
    /// </summary>
    public static class LogText
    {
        /// <summary>
        /// Identifies a SAML message for the log by its element name, ID, InResponseTo, IssueInstant and Issuer,
        /// without its content.
        /// </summary>
        public static string Describe(XmlElement message)
        {
            if (message == null)
                return "<no message>";

            var description = new StringBuilder(message.LocalName);
            foreach (var attribute in new[] { "ID", "InResponseTo", "IssueInstant" })
            {
                if (message.HasAttribute(attribute))
                    description.Append(' ').Append(attribute).Append('=').Append(message.GetAttribute(attribute));
            }

            var issuer = message["Issuer", Saml20Constants.ASSERTION];
            if (issuer != null)
                description.Append(" Issuer=").Append(issuer.InnerText.Trim());

            return OneLine(description.ToString());
        }

        /// <summary>
        /// Identifies a SAML message for the log, as <see cref="Describe(XmlElement)"/>.
        /// </summary>
        public static string Describe(string message)
        {
            try
            {
                return Describe(SafeXml.Load(message).DocumentElement);
            }
            catch (Exception)
            {
                return "<unreadable message>";
            }
        }

        /// <summary>
        /// The session id is what makes a request part of the session, so the log gets a hash that only correlates entries.
        /// </summary>
        internal static string HashSessionId(Guid sessionId)
        {
            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(sessionId.ToByteArray());
                return BitConverter.ToString(hash, 0, 8).Replace("-", "").ToLowerInvariant();
            }
        }

        internal static string OneLine(string value)
        {
            return value?.Replace("\r", "\\r").Replace("\n", "\\n");
        }
    }
}
