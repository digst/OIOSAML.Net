using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Caching;

namespace dk.nita.saml20.session.inproc
{
    internal class InProcSessions : AbstractSessions
    {
        private static readonly Cache Sessions = HttpRuntime.Cache;

        private const string UserId = "UserId";


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

                    // Ping user id cache to extend the timeout
                    var userId = session[UserId] as string;
                    if (!string.IsNullOrEmpty(userId))
                    {
                        if (Sessions[userId] == null)
                        {
                            // DO NOTHING. We just wanted to renew the session timeout on user id cache.
                        }

                    }
                }
            }

            if (session == null)
            {
                session = CreateSession();
                session.New = true;
            }
            return session;
        }

        public override void AbandonAllSessions(string userId)
        {
            string userIdLowerCase = userId.ToLower();
            IList<Guid> sessionIds = Sessions[userIdLowerCase] as IList<Guid>;

            if (sessionIds != null)
            {
                foreach (var sessionId in sessionIds)
                {
                    Sessions.Remove(sessionId.ToString());
                }
            }

            Sessions.Remove(userIdLowerCase);
        }

        public override void AssociateUserIdWithCurrentSession(string userId)
        {
            string userIdLowerCase = userId.ToLower();
            IList<Guid> sessionIds = Sessions[userIdLowerCase] as IList<Guid>;

            if (sessionIds == null)
            {
                sessionIds = new List<Guid>();
                Sessions.Insert(userIdLowerCase, sessionIds, null, Cache.NoAbsoluteExpiration, new TimeSpan(0, 0, SessionTimeout, 0));
            }

            // Update cache from user id perspective
            sessionIds = Sessions[userIdLowerCase] as IList<Guid>;
            sessionIds.Add(Current.Id);

            // Update cache from session id perspective so that we have a bi-directional reference.
            Current[UserId] = userIdLowerCase;
        }

        public override void AbandonCurrentSession()
        {
            if (SessionId.HasValue)
            {
                Sessions.Remove(SessionId.ToString()); // Remove is thread safe. No need to lock.
            }
        }

        private ISession CreateSession()
        {
            Guid sessionId = Guid.NewGuid();
            var session = new InProcSession(sessionId);
            Sessions.Insert(sessionId.ToString(), session, null, Cache.NoAbsoluteExpiration, new TimeSpan(0, 0, SessionTimeout, 0));
            return session;
        }
    }
}
