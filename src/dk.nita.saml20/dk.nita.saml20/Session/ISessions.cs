using System;
using System.ServiceModel.Channels;

namespace dk.nita.saml20.session
{
    /// <summary>
    /// This interface is used for working with session state. It makes it possible to access all sessions at any time.
    /// The purpose of this interface is to support SOAP Logout which was not possible with ASP.NET session state.
    /// With this interface it is up to the Service Provider to decide if a simple InProc implementation is enough or OutProc is needed due to a load balancing setup. Also, sticky session can be avoided with an OutProc implementation.
    /// Some of the method implementations of this interface must be tread safe. Only those methods that must be thread safe are marked as such. Methods not marked as thread safe are guaranteed only to be called by one thread at a time.
    /// </summary>
    interface ISessions
    {
        /// <summary>
        /// Gets the current session. Accessing the session must result in the session timeout being reset. Thus, it must work according to the sliding expiration principle.
        /// If no session exist a new one must be returned where <see cref="ISession.New"/> must be true for the remaining of the HTTP request.
        /// </summary>
        /// <returns>The current session or null if none exists</returns>
        ISession Current { get; }

        /// <summary>
        /// Abondon a arbitrary session given a session id. Returns without error if the session could not be found.
        /// Is thread safe.
        /// </summary>
        /// <param name="sessionId">Id of the session to abandon</param>
        void AbandonSession(Guid sessionId);

        /// <summary>
        /// Abondon the current session. Returns without error if the current session could not be found.
        /// Is thread safe.
        /// </summary>
        void AbandonCurrentSession();

        ///// <summary>
        ///// Creates a session with the id taken from the cookie with name <see cref="SessionConstants.SessionCookieName"/>.
        ///// Use <see cref="Current" /> prior to creating a session.
        ///// Is thread safe.
        ///// </summary>
        ///// <exception cref="InvalidOperationException">Is thrown if a session with the given id already exists.</exception>
        //void CreateSession();
    }
}
