using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;

namespace dk.nita.saml20.Logging
{
    /// <summary>
    /// An implementation of the IAuditLogger interface that uses the System.Diagnostics Trace functionality to audit log.
    /// </summary>
    class TraceAuditLogger : IAuditLogger
    {
        /// <summary>
        /// The source to use for logging
        /// </summary>
        private readonly static TraceSource _source;

        static TraceAuditLogger()
        {
            _source = new TraceSource("dk.nita.saml20.auditLogger");
        }

        public void LogEntry(Direction dir, Operation op, string msg, string data, string userHostAddress, string idpId, string assertionId, string sessionId)
        {
            if (_source.Switch.ShouldTrace(TraceEventType.Information))
            {
                var str = String.Format("Session id: {6}, Direction: {0}, Operation: {1}, User IP: {2}, Idp ID: {3}, Assertion ID: {4}, Message: {5}, Data: {7}", dir, op, userHostAddress, idpId, assertionId, msg, sessionId, data != null ? data : "");
                _source.TraceData(TraceEventType.Information, 0, str);
            }
        }
    }
}
