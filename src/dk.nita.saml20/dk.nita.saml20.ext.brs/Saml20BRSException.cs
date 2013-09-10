using System;
using System.Collections.Generic;
using System.Text;

namespace dk.nita.saml20.ext.brs
{
    public class Saml20BRSException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20BRSException"/> class.
        /// </summary>
        public Saml20BRSException() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20BRSException"/> class.
        /// </summary>
        /// <param name="msg">The MSG.</param>
        public Saml20BRSException(string msg) : base(msg) { }
        
        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20BRSException"/> class.
        /// </summary>
        /// <param name="msg">A message describing the problem that caused the exception.</param>
        /// <param name="cause">Another exception that may be related to the problem.</param>
        public Saml20BRSException(string msg, Exception cause) : base(msg, cause) { }
    }
}
