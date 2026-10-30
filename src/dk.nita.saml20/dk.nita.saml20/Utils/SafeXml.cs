using System.IO;
using System.Xml;

namespace dk.nita.saml20.Utils
{
    /// <summary>
    /// Parses XML received from other parties: DTDs are refused and no external resources are read.
    /// </summary>
    internal static class SafeXml
    {
        private static XmlReaderSettings Settings()
        {
            return new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        }

        /// <summary>
        /// Loads a document that keeps its whitespace, as signature checks need.
        /// </summary>
        internal static XmlDocument Load(string xml)
        {
            return Load(new StringReader(xml));
        }

        /// <summary>
        /// Loads a document that keeps its whitespace, as signature checks need.
        /// </summary>
        internal static XmlDocument Load(TextReader input)
        {
            var doc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
            using (var reader = XmlReader.Create(input, Settings()))
            {
                doc.Load(reader);
            }
            return doc;
        }

        /// <summary>
        /// Loads a document that declares its own encoding, such as a metadata file, keeping its whitespace.
        /// </summary>
        internal static XmlDocument Load(Stream input)
        {
            var doc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
            using (var reader = XmlReader.Create(input, Settings()))
            {
                doc.Load(reader);
            }
            return doc;
        }

        /// <summary>
        /// Creates a reader for deserializing XML received from other parties.
        /// </summary>
        internal static XmlReader CreateReader(string xml)
        {
            return XmlReader.Create(new StringReader(xml), Settings());
        }
    }
}
