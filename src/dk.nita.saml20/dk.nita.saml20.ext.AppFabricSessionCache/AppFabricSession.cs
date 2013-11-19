using System;
using System.Collections.Generic;
using Microsoft.ApplicationServer.Caching;
using dk.nita.saml20.session;

namespace dk.nita.saml20.ext.appfabricsessioncache
{
    class AppFabricSession : ISession
    {
        private static readonly DataCacheFactory CacheFactory = new DataCacheFactory();

        private readonly Guid _sessionId;

        public AppFabricSession(Guid sessionId)
        {
            _sessionId = sessionId;
        }

        public object this[string key]
        {
            get
            {
                DataCache sessions = CacheFactory.GetDefaultCache();
                var session = sessions.Get(_sessionId.ToString()) as IDictionary<string, object>;
                if (session != null)
                    return session[key];
                
                return null;
            }
            set
            {
                DataCache sessions = CacheFactory.GetDefaultCache();
                var session = sessions.Get(_sessionId.ToString()) as IDictionary<string, object>;
                if (session != null)
                {
                    session[key] = value;
                    sessions.Put(_sessionId.ToString(), session);
                }
                else
                 throw new InvalidOperationException("Session with session id: " + _sessionId + " does not exist. Not able to add key: " + key + " and value: " + value +" to session.");
            }
        }

        public void Remove(string key)
        {
            DataCache sessions = CacheFactory.GetDefaultCache();
            var session = sessions.Get(_sessionId.ToString()) as IDictionary<string, object>;
            if (session != null)
            {
                session.Remove(key);
                sessions.Put(_sessionId.ToString(), session);
            }
            else
                throw new InvalidOperationException("Session with session id: " + _sessionId + " does not exist. Not able to remove key: " + key + " from session.");
        }
    }
}
