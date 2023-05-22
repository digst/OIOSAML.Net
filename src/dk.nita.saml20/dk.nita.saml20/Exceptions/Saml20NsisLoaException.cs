using System;

namespace dk.nita.saml20
{
    /// <summary>
    /// This exception is thrown to indicate a non sufficient LOA level during the signon request. It was introduced to make it easy to distinguish between
    /// exceptions thrown deliberately by the toolkit, and exceptions that are thrown as the result of bugs.
    /// </summary>
    public class Saml20NsisLoaException : Saml20Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20NsisLoaException"/> class.
        /// </summary>
        public Saml20NsisLoaException() : base() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20NsisLoaException"/> class.
        /// </summary>
        /// <param name="msg">The MSG.</param>
        public Saml20NsisLoaException(string msg) : base(msg) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20NsisLoaException"/> class.
        /// </summary>
        /// <param name="msg">A message describing the problem that caused the exception.</param>
        /// <param name="cause">Another exception that may be related to the problem.</param>
        public Saml20NsisLoaException(string msg, Exception cause) : base(msg, cause) { }
    }
}