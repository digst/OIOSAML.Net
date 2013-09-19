using System;
using System.Collections.Generic;
using System.Text;
using System.Web;
using System.Xml;
using dk.nita.saml20.identity;
using dk.nita.saml20.Schema.Metadata;
using log4net;
using log4net.Repository.Hierarchy;

namespace dk.nita.saml20.Logging
{
    ///<summary>
    ///</summary>
    public class AuditLogging
    {
        static AuditLogging()
        {
            //AuditLogger = new Log4NetAuditLogger();
            AuditLogger = new TraceAuditLogger();
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

            logEntry(Direction.UNDEFINED, Operation.LOGIN_PERSISTENT_PSEUDONYME, string.Format("Authenticated nameid: {0} as local user id: {1}, auth.level: {2}, session timeout in minutes: {3}", nameid, localuserid, currentAuthLevel, HttpContext.Current.Session.Timeout));
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
            AuditLogger.logEntry(dir, op, msg, data, HttpContext.Current.Request.UserHostAddress, IdpId, AssertionId, HttpContext.Current.Session.SessionID);
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
