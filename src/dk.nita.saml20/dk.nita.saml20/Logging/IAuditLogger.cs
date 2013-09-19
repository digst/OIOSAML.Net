using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace dk.nita.saml20.Logging
{
    /// <summary>
    /// 
    /// </summary>
    public interface IAuditLogger
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="dir"></param>
        /// <param name="op"></param>
        /// <param name="msg"></param>
        /// <param name="data"></param>
        /// <param name="userHostAddress"></param>
        /// <param name="idpId"></param>
        /// <param name="assertionId"></param>
        /// <param name="sessionId"></param>
        void logEntry(Direction dir, Operation op, string msg, string data, string userHostAddress, string idpId, string assertionId, string sessionId);
    }
}
