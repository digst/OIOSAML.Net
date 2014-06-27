using System;
using System.Collections.Generic;
using Microsoft.ApplicationServer.Caching;
using dk.nita.saml20.session;

namespace dk.nita.saml20.ext.appfabricsessioncache
{
    public class AppFabricSessions : AbstractSessions
    {
        private static readonly object Locker = new object();

        private const string UserId = "UserId";

        // Use configuration from the application configuration file.
        private static readonly DataCacheFactory CacheFactory = new DataCacheFactory();

        public static string CacheName;

        static AppFabricSessions()
        {
            CacheName = System.Configuration.ConfigurationManager.AppSettings["CacheName"];
            if (CacheName == null)
                throw new InvalidOperationException("Not able to initialize AppFabricSessions because no app setting with key CacheName was found.");
        }

        protected override ISession GetSession()
        {
            ISession session = null;
            DataCache sessions = CacheFactory.GetCache(CacheName);
            if (SessionId.HasValue && sessions.Get(SessionId.ToString()) != null)
            {
                try
                {
                    // Needed in order to simluate sliding expiration
                    sessions.ResetObjectTimeout(SessionId.ToString(), new TimeSpan(0, 0, SessionTimeout, 0));
                    session = new AppFabricSession(SessionId.Value);

                    // Ping user id cache to extend the timeout
                    var userId = session[UserId] as string;
                    if (!string.IsNullOrEmpty(userId))
                    {
                        sessions.ResetObjectTimeout(userId, new TimeSpan(0, 0, SessionTimeout, 0));
                    }
                }
                catch (DataCacheException)
                {
                    // Do nothing - call to sessions.ResetObjectTimeout will throw a DataCacheException if sessions have been removed by SOAP-Logout
                }
            }

            if (session == null)
            {
                session = new AppFabricSession(CreateSession());
                session.New = true;
            }

            return session;
        }

        public override void AbandonAllSessions(string userId)
        {
            string userIdLowerCase = userId.ToLower();
            DataCache sessions = CacheFactory.GetCache(CacheName);
            var sessionIds = sessions[userIdLowerCase] as IList<Guid>;

            if (sessionIds != null)
            {
                foreach (var sessionId in sessionIds)
                {
                    sessions.Remove(sessionId.ToString());
                }
            }

            sessions.Remove(userIdLowerCase);
        }

        public override void AssociateUserIdWithCurrentSession(string userId)
        {
            string userIdLowerCase = userId.ToLower();
            DataCache sessions = CacheFactory.GetCache(CacheName);
            IList<Guid> sessionIds = sessions[userIdLowerCase] as IList<Guid>;

            if (sessionIds == null)
            {
                sessionIds = new List<Guid>();
                sessions.Add(userIdLowerCase, sessionIds, new TimeSpan(0, 0, SessionTimeout, 0));
            }

            // Update cache from user id perspective
            sessionIds = sessions[userIdLowerCase] as IList<Guid>;
            sessionIds.Add(Current.Id);
            sessions.Put(userIdLowerCase, sessionIds);

            // Update cache from session id perspective so that we have a bi-directional reference.
            Current[UserId] = userIdLowerCase;
        }

        public override void AbandonCurrentSession()
        {
            if (SessionId.HasValue)
            {
                lock (Locker)
                {
                    DataCache sessions = CacheFactory.GetCache(CacheName);
                    sessions.Remove(SessionId.ToString()); // Remove is not thread safe.
                }
            }
        }

        private Guid CreateSession()
        {
            Guid sessionId = Guid.NewGuid();
            DataCache sessions = CacheFactory.GetCache(CacheName);

            sessions.Add(sessionId.ToString(), new Dictionary<string, object>(), new TimeSpan(0, 0, SessionTimeout, 0));

            return sessionId;
        }
    }
}
