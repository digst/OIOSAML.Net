using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using log4net;

namespace dk.nita.saml20.Logging
{
    /// <summary>
    /// An implementation of the IAuditLogger interface that uses the log4net functionality to audit log.
    /// </summary>
    public class Log4NetAuditLogger : IAuditLogger
    {
        private static ILog logger = LogManager.GetLogger("OIOSAML_AUDIT_LOGGER");

        static Log4NetAuditLogger()
        {
            log4net.Config.XmlConfigurator.Configure();
        }

        public void LogEntry(Direction dir, Operation op, string msg, string data, string userHostAddress, string idpId, string assertionId, string sessionId)
        {
            logger.Info(String.Format("Session id: {6}, Direction: {0}, Operation: {1}, User IP: {2}, Idp ID: {3}, Assertion ID: {4}, Message: {5}, Data: {7}", dir, op, userHostAddress, idpId, assertionId, msg, sessionId, data != null ? data : ""));
        }
    }
}
