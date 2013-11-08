using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace dk.nita.saml20.Logging
{
    /// <summary>
    /// Defines the behaviour of an audit logger that logs an audit trail
    /// </summary>
    public interface IAuditLogger
    {
        /// <summary>
        /// Logs the record
        /// </summary>
        /// <param name="dir">The direction</param>
        /// <param name="op">The operation</param>
        /// <param name="msg">The message to log</param>
        /// <param name="data">Extra data to log</param>
        /// <param name="userHostAddress">The ip adress of the user</param>
        /// <param name="idpId">The id of the idp</param>
        /// <param name="assertionId">The id of the assertion</param>
        /// <param name="sessionId">The id of the session</param>
        void LogEntry(Direction dir, Operation op, string msg, string data, string userHostAddress, string idpId, string assertionId, string sessionId);
    }
}
