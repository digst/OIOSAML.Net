using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;

namespace dk.nita.saml20.Session
{
    /// <summary>
    /// Stores sessions in process memory. Expired sessions and user associations are automatically cleaned up
    /// </summary>
    public class InProcSessionStoreProvider : ISessionStoreProvider
    {
        class Session
        {
            internal DateTime Timestamp { get; }
            internal ConcurrentDictionary<string, object> Properties { get; }

            public Session()
            {
                Timestamp = DateTime.UtcNow;
                Properties = new ConcurrentDictionary<string, object>();
            }
        }

        readonly ConcurrentDictionary<Guid, Session> _sessions = new ConcurrentDictionary<Guid, Session>();
        readonly ConcurrentDictionary<Guid, string> _userAssociations = new ConcurrentDictionary<Guid, string>();
        private TimeSpan _sessionTimeout;

        /// <summary>
        /// 
        /// </summary>
        public InProcSessionStoreProvider()
        {
            var timer = new Timer(Cleanup, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
        }

        private void Cleanup(object state)
        {
            foreach (var s in _sessions)
            {
                if (s.Value.Timestamp + _sessionTimeout < DateTime.UtcNow)
                {
                    Session d;
                    _sessions.TryRemove(s.Key, out d);
                }
            }

            foreach (var ua in _userAssociations)
            {
                if (!_sessions.ContainsKey(ua.Key))
                {
                    string d;
                    _userAssociations.TryRemove(ua.Key, out d);
                }
            }
        }

        void ISessionStoreProvider.SetSessionProperty(Guid sessionId, string key, object value)
        {
            var session = _sessions.GetOrAdd(sessionId, new Session());
            session.Properties.AddOrUpdate(key, value, (k,e) => value);
        }

        void ISessionStoreProvider.RemoveSessionProperty(Guid sessionId, string key)
        {
            Session session;
            if (_sessions.TryGetValue(sessionId, out session))
            {
                object val;
                session.Properties.TryRemove(key, out val);
            }
        }

        object ISessionStoreProvider.GetSessionProperty(Guid sessionId, string key)
        {
            Session session;
            if (_sessions.TryGetValue(sessionId, out session))
            {
                object val;
                if (session.Properties.TryGetValue(key, out val))
                {
                    return val;
                }
            }

            return null;
        }

        void ISessionStoreProvider.AssociateUserIdWithSessionId(string userId, Guid sessionId)
        {
            _userAssociations.AddOrUpdate(sessionId, userId, (k, e) => userId);
        }

        void ISessionStoreProvider.AbandonSessionsAssociatedWithUserId(string userId)
        {
            var sessions = _userAssociations
                .Where(x => x.Value == userId)
                .Select(x => x.Key)
                .ToList();

            foreach (var s in sessions)
            {
                Session val;
                _sessions.TryRemove(s, out val);
                string user;
                _userAssociations.TryRemove(s, out user);
            }
        }

        void ISessionStoreProvider.Initialize(TimeSpan sessionTimeout)
        {
            _sessionTimeout = sessionTimeout;
        }
    }
}