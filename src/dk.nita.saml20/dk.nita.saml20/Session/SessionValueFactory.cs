using System;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace dk.nita.saml20.Session
{
    class SessionValueFactory : ISessionValueFactory
    {
        public string Serialize(object value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));

            var sb = new StringBuilder();

            using (var writer = XmlWriter.Create(sb))
            {
                new XmlSerializer(value.GetType()).Serialize(writer, value);
            }

            return sb.ToString();
        }

        public object Deserialize(Type valueType, string valueString)
        {
            if (valueType == null) throw new ArgumentNullException(nameof(valueType));
            if (valueString == null) throw new ArgumentNullException(nameof(valueString));

            using (var stringReader = new StringReader(valueString))
            {
                using (var reader = XmlReader.Create(stringReader))
                {
                    return new XmlSerializer(valueType).Deserialize(reader);

                }
            }
        }
    }
}