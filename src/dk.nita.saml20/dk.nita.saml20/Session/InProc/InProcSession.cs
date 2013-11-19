using System.Collections.Generic;

namespace dk.nita.saml20.session.inproc
{
    class InProcSession : ISession
    {
        private readonly IDictionary<string, object> _dictionary =  new Dictionary<string, object>();
        
        public object this[string key]
        {
            get { return _dictionary[key]; }
            set { _dictionary[key] = value; }
        }

        public void Remove(string key)
        {
            _dictionary.Remove(key);
        }
    }
}
