using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;
using dk.nita.saml20.Logging;

namespace dk.nita.test.Logging
{
    [TestFixture]
    public class AuditLoggingTest
    {
        /// <summary>
        /// Test the configuration and initialisation part of the AuditLogging class.
        /// </summary>
        [Test]
        public void AuditLoggerConfigurationTest()
        {
            AuditLoggerMock.LogEntryCalledCount = 0;
            Assert.IsTrue(AuditLoggerMock.LogEntryCalledCount == 0);
            AuditLogging.logEntry(Direction.IN, Operation.LOGIN, "Testing");
            Assert.IsTrue(AuditLoggerMock.LogEntryCalledCount > 0);
        }
    }

    /// <summary>
    /// A mock implementation of the IAuditLogger interface used for testing
    /// </summary>
    public class AuditLoggerMock : IAuditLogger
    {
        public static int LogEntryCalledCount { get; set; }

        public void logEntry(Direction dir, Operation op, string msg, string data, string userHostAddress, string idpId, string assertionId, string sessionId)
        {
            LogEntryCalledCount++;
        }
    }
}
