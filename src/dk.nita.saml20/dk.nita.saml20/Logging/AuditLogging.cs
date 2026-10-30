using System;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Xml;
using dk.nita.saml20.config;
using dk.nita.saml20.Utils;
using dk.nita.saml20.Session;

namespace dk.nita.saml20.Logging
{
    ///<summary>
    ///</summary>
    public class AuditLogging
    {
        static AuditLogging()
        {
            var type = FederationConfig.GetConfig().AuditLoggingType;
            if (!string.IsNullOrEmpty(type))
            {
                try
                {
                    var t = Type.GetType(type);
                    if (t != null)
                    {
                        AuditLogger = (IAuditLogger)Activator.CreateInstance(t);
                    }
                    else
                    {
                        throw new Exception(string.Format("The type {0} is not available for the audit logging. Please check the type name and assembly", type));
                    }
                }
                catch (Exception e)
                {
                    Trace.TraceData(System.Diagnostics.TraceEventType.Critical, "Could not instantiate the configured auditLogger. Message: " + e.Message);
                    throw;
                }
            }
            else
            {
                AuditLogger = new TraceAuditLogger();
            }
        }

        private static readonly IAuditLogger AuditLogger;

        ///<summary>
        ///</summary>
        public static string AssertionId
        {
            get { return HttpContext.Current.Items["AuditLogging:AssertionId"] as string; }
            set { HttpContext.Current.Items["AuditLogging:AssertionId"] = value; }
        }
        ///<summary>
        ///</summary>
        public static string IdpId
        {
            get { return HttpContext.Current.Items["AuditLogging:IdpId"] as string; }
            set { HttpContext.Current.Items["AuditLogging:IdpId"] = value; }
        }

        ///<summary>
        ///</summary>
        ///<param name="dir"></param>
        ///<param name="op"></param>
        ///<param name="msg"></param>
        public static void logEntry(Direction dir, Operation op, String msg)
        {
            logEntry(dir, op, msg, string.Empty);
        }


        ///<summary>
        ///</summary>
        ///<param name="dir"></param>
        ///<param name="op"></param>
        public static void logEntry(Direction dir, Operation op)
        {
            logEntry(dir, op, "");
        }

        ///<summary>
        ///</summary>
        ///<param name="dir"></param>
        ///<param name="op"></param>
        ///<param name="msg"></param>
        ///<param name="data"></param>
        public static void logEntry(Direction dir, Operation op, string msg, XmlElement data)
        {
            logEntry(dir, op, msg, Describe(data));
        }

        ///<summary>
        ///</summary>
        ///<param name="dir"></param>
        ///<param name="op"></param>
        ///<param name="msg"></param>
        ///<param name="data"></param>
        public static void logEntry(Direction dir, Operation op, string msg, string data)
        {
            var userHostAddress = HttpContext.Current != null ? HttpContext.Current.Request.UserHostAddress : "<no ip>";
            var sessionId = SessionStore.CurrentSession != null ? HashSessionId(SessionStore.CurrentSession.SessionId) : "<no session id>";

            AuditLogger.LogEntry(dir, op, OneLine(msg), OneLine(data), userHostAddress, OneLine(IdpId), OneLine(AssertionId), sessionId);
        }

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
    ///<summary>
    ///</summary>
    public enum Operation
    {
        ///<summary>
        ///</summary>
        AUTHNREQUEST_SEND,
        ///<summary>
        ///</summary>
        AUTHNREQUEST_REDIRECT_ARTIFACT,
        ///<summary>
        ///</summary>
        AUTHNREQUEST_REDIRECT,
        ///<summary>
        ///</summary>
        AUTHNREQUEST_POST,
        ///<summary>
        ///</summary>
        ATTRIBUTEQUERY,
        ///<summary>
        ///</summary>
        LOGOUTREQUEST,
        ///<summary>
        ///</summary>
        LOGOUT,
        ///<summary>
        ///</summary>
        LOGOUTRESPONSE,
        ///<summary>
        ///</summary>
        ARTIFACTRESOLVE,
        ///<summary>
        ///</summary>
        LOGIN,
        ///<summary>
        ///</summary>
        LOGOUT_SOAP,
        ///<summary>
        ///</summary>
        ACCESS,
        ///<summary>
        ///</summary>
        DISCOVER,
        ///<summary>
        ///</summary>
        TIMEOUT,
        ///<summary>
        ///</summary>
        CRLCHECK,
        ///<summary>
        ///</summary>
        LOGIN_SESSION
    }

    ///<summary>
    ///</summary>
    public enum Direction
    {
        ///<summary>
        ///</summary>
        UNDEFINED,
        ///<summary>
        ///</summary>
        IN,
        ///<summary>
        ///</summary>
        OUT
    }

}
