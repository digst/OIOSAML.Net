using System;
using System.Collections.Generic;
using Microsoft.ApplicationServer.Caching;
using dk.nita.saml20.session;

namespace dk.nita.saml20.ext.appfabricsessioncache
{
    class AppFabricSession : ISession
    {
        private static readonly DataCacheFactory CacheFactory = new DataCacheFactory();

        public AppFabricSession(Guid sessionId)
        {
            Id = sessionId;
        }

        public object this[string key]
        {
            get
            {
                DataCache sessions = CacheFactory.GetCache(AppFabricSessions.CacheName);
                var session = sessions.Get(Id.ToString()) as IDictionary<string, object>;
                if (session != null && session.ContainsKey(key))
                    return session[key];
                
                return null;
            }
            set
            {
                DataCache sessions = CacheFactory.GetCache(AppFabricSessions.CacheName);
                var session = sessions.Get(Id.ToString()) as IDictionary<string, object>;
                if (session != null)
                {
                    session[key] = value;
                    sessions.Put(Id.ToString(), session);
                }
                else
                 throw new InvalidOperationException("Session with session id: " + Id + " does not exist. Not able to add key: " + key + " and value: " + value +" to session.");
            }
        }

        public void Remove(string key)
        {
            DataCache sessions = CacheFactory.GetCache(AppFabricSessions.CacheName);
            var session = sessions.Get(Id.ToString()) as IDictionary<string, object>;
            if (session != null)
            {
                session.Remove(key);
                sessions.Put(Id.ToString(), session);
            }
            else
                throw new InvalidOperationException("Session with session id: " + Id + " does not exist. Not able to remove key: " + key + " from session.");
        }

        public bool New { get; set; }

        public Guid Id { get; private set; }
    }
}
