using System;
using System.Web;
using System.Web.Caching;

namespace dk.nita.saml20.session.inproc
{
    internal class InProcSessions : AbstractSessions
    {
        private static readonly Cache Sessions = HttpRuntime.Cache;

        protected override ISession GetSession()
        {
            ISession session = null;
            if (SessionId.HasValue)
            {
                session = Sessions[SessionId.ToString()] as ISession;
                if (session != null)
                {
                    // Set to false as it already existed.
                    session.New = false;
                }
            }

            if (session == null)
            {
                session = CreateSession();
                session.New = true;
            }
            return session;
        }

        public override void AbandonSession(Guid sessionId)
        {
            if (SessionId.HasValue)
            {
                Sessions.Remove(sessionId.ToString()); // Remove is thread safe. No need to lock.
            }
        }

        private ISession CreateSession()
        {
            Guid sessionId = Guid.NewGuid();
            var session = new InProcSession(sessionId);
            Sessions.Insert(sessionId.ToString(), session, null,
                            Cache.NoAbsoluteExpiration, new TimeSpan(0, 0, SessionTimeout, 0));
            return session;
        }
    }
}
