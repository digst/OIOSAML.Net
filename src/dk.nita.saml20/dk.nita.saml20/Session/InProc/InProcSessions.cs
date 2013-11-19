using System;
using System.Web;
using System.Web.Caching;

namespace dk.nita.saml20.session.inproc
{
    internal class InProcSessions : AbstractSessions
    {
        private static readonly object Locker = new object();

        private static readonly Cache Sessions = HttpRuntime.Cache;

        public override ISession Current
        {
            get
            {
                if (SessionId.HasValue)
                {
                    return Sessions[SessionId.ToString()] as ISession;
                }
                return null;
            }
        }

        public override void AbandonSession(Guid sessionId)
        {
            if (SessionId.HasValue)
            {
                Sessions.Remove(sessionId.ToString()); // Remove is thread safe. No need to lock.
            }
        }

        public override void CreateSession()
        {
            lock (Locker)
            {
                if (SessionExists())
                    throw new InvalidOperationException("A session with id: " + SessionId + " already exists!!!");
                if (SessionId == null)
                    throw new InvalidOperationException("Not able to create session a because SessionId is not set!!!");

                Sessions.Insert(SessionId.ToString(), new InProcSession(), null,
                                Cache.NoAbsoluteExpiration, new TimeSpan(0, 0, SessionTimeout, 0));
            }
        }
    }
}
