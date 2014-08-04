using System;
using System.Collections.Generic;
using System.Text;
using System.Web;
using System.Xml;
using dk.nita.saml20.identity;
using dk.nita.saml20.Schema.Metadata;
using dk.nita.saml20.config;
using dk.nita.saml20.Utils;
using dk.nita.saml20.session;

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

        private static IAuditLogger AuditLogger;
        
        ///<summary>
        ///</summary>
        [ThreadStatic] public static string AssertionId;
        ///<summary>
        ///</summary>
        [ThreadStatic] public static string IdpId;

        ///<summary>
        /// Call from SP when using persistent psuedonyme profile
        ///</summary>
        ///<param name="nameid"></param>
        ///<param name="localuserid"></param>
        public static void LogPersistentPseudonymAuthenticated(string nameid, string localuserid)
        {
            string currentAuthLevel = "Unknown";
            if (Saml20Identity.IsInitialized() && Saml20Identity.Current != null)
            {
                currentAuthLevel = Saml20Identity.Current["dk:gov:saml:attribute:AssuranceLevel"][0].AttributeValue[0];
            }

            logEntry(Direction.UNDEFINED, Operation.LOGIN_PERSISTENT_PSEUDONYME, string.Format("Authenticated nameid: {0} as local user id: {1}, auth.level: {2}, session timeout in minutes: {3}", nameid, localuserid, currentAuthLevel, FederationConfig.GetConfig().SessionTimeout));
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
            var sessionId = SessionFactory.SessionContext.Current != null ? SessionFactory.SessionContext.Current.Id.ToString() : "<no session id>";

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
        LOGIN_SESSION,
        ///<summary>
        ///</summary>
        LOGIN_PERSISTENT_PSEUDONYME

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
