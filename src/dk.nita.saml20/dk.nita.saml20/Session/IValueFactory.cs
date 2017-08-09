using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace dk.nita.saml20.Session
{
    /// <summary>
    /// 
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
