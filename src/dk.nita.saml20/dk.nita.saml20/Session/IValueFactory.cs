using System;

namespace dk.nita.saml20.Session
{
    /// <summary>
    /// Add support for a safe way of serializing value objects if the <see cref="ISessionStoreProvider"/> needs to persist values
    /// </summary>
    public interface ISessionValueFactory
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        string Serialize(object value);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="valueType"></param>
        /// <param name="valueString"></param>
        /// <returns></returns>
        object Deserialize(Type valueType, string valueString);
    }
}
