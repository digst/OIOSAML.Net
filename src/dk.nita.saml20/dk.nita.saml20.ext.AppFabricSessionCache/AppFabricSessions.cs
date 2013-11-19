using System;
using System.Collections.Generic;
using Microsoft.ApplicationServer.Caching;
using dk.nita.saml20.session;

namespace dk.nita.saml20.ext.appfabricsessioncache
{
    public class AppFabricSessions : AbstractSessions
    {
        private static readonly object Locker = new object();

        // Use configuration from the application configuration file.
        private static readonly DataCacheFactory CacheFactory = new DataCacheFactory();

        public override ISession Current
        {
            get
            {
                DataCache sessions = CacheFactory.GetDefaultCache();
                if (SessionId.HasValue && sessions.Get(SessionId.ToString()) != null)
                {
                    sessions.ResetObjectTimeout(SessionId.ToString(), new TimeSpan(0, 0, 30, 0)); // Needed in order to simluate sliding expiration
                    return new AppFabricSession(SessionId.Value);
                }
                return null;
            } 
        }

        public override void AbandonSession(Guid sessionId)
        {
            lock (Locker)
            {
                DataCache sessions = CacheFactory.GetDefaultCache();
                sessions.Remove(sessionId.ToString()); // Remove is not thread safe.
            }
        }

        public override void CreateSession()
        {
            lock (Locker)
            {
                if (SessionExists())
                    throw new InvalidOperationException("A session with id: " + SessionId + " already exists!!!");
                if(SessionId == null)
                    throw new InvalidOperationException("Not able to create a session because SessionId is not set!!!");

                DataCache sessions = CacheFactory.GetDefaultCache();

                sessions.Add(SessionId.ToString(), new Dictionary<string, object>(), new TimeSpan(0, 0, SessionTimeout, 0));
            }
        }
    }
}
