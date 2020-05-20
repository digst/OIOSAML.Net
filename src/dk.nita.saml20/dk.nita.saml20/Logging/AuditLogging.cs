using System;
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
            logEntry(dir, op, msg, data.OuterXml);
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
            var sessionId = SessionStore.CurrentSession != null ? SessionStore.CurrentSession.SessionId.ToString() : "<no session id>";

            AuditLogger.LogEntry(dir, op, msg, data, userHostAddress, IdpId, AssertionId, sessionId);
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
