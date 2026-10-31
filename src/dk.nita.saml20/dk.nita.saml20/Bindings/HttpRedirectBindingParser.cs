using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Xml;
using dk.nita.saml20.Bindings.SignatureProviders;
using dk.nita.saml20.Schema.Metadata;
using dk.nita.saml20.Schema.Protocol;
using dk.nita.saml20.Utils;
using CONSTS = dk.nita.saml20.Bindings.HttpRedirectBindingConstants;

namespace dk.nita.saml20.Bindings
{
    /// <summary>
    /// Parses and validates the query parameters of a HttpRedirectBinding. [SAMLBind] section 3.4.
    /// </summary>
    public class HttpRedirectBindingParser
    {
        /// <summary>
        /// Parses the query string.
        /// </summary>
        /// <param name="uri">The URL that the user was redirected to by the IDP. It is essential for the survival of the signature,
        /// that the URL is not modified in any way, eg. by URL-decoding it.</param>
        public HttpRedirectBindingParser(Uri uri)
        {
            Dictionary<string, string> paramDict = ToDictionary(uri);

            foreach (KeyValuePair<string, string> param in paramDict)
                SetParam(param.Key, HttpUtility.UrlDecode(param.Value));

            if (_message == null)
                throw new Saml20FormatException("The query contains neither a SAMLRequest nor a SAMLResponse.");

            // If the message is signed, save the original, encoded parameters so that the signature can be verified.
            if (IsSigned)
                CreateSignatureSubject(paramDict);

            ReadMessageParameter();
        }

        private static readonly string[] BindingParameters = { CONSTS.SAMLRequest, CONSTS.SAMLResponse, CONSTS.RelayState, CONSTS.SigAlg, CONSTS.Signature };

        /// <summary>
        /// The binding parameters of the query, with their values still URL-encoded. Other parameters are left out.
        /// The signature is verified over these values and the message is read from them, so a binding parameter must
        /// appear once, with its name spelt as in [SAMLBind] 3.4.4.1. Names are compared URL-decoded, as ASP.NET reads them.
        /// </summary>
        /// <exception cref="Saml20FormatException">If a binding parameter appears more than once, in any letter case,
        /// both a SAMLRequest and a SAMLResponse are present, or a Signature comes without a SigAlg.</exception>
        private static Dictionary<string, string> ToDictionary(Uri uri)
        {
            var result = new Dictionary<string, string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var query = uri.Query.Length > 0 ? uri.Query.Substring(1) : string.Empty;
            foreach (string s in query.Split('&'))
            {
                var separator = s.IndexOf('=');
                var name = HttpUtility.UrlDecode(separator < 0 ? s : s.Substring(0, separator));
                var value = separator < 0 ? string.Empty : s.Substring(separator + 1);

                var parameter = Array.Find(BindingParameters, p => string.Equals(p, name, StringComparison.OrdinalIgnoreCase));
                if (parameter == null)
                    continue;
                if (!seen.Add(name) || parameter != name)
                    throw new Saml20FormatException($"The query parameter {parameter} must appear once, spelt {parameter}.");
                result.Add(name, value);
            }

            if (result.ContainsKey(CONSTS.SAMLRequest) && result.ContainsKey(CONSTS.SAMLResponse))
                throw new Saml20FormatException("The query contains both a SAMLRequest and a SAMLResponse.");
            if (result.ContainsKey(CONSTS.Signature) && !result.ContainsKey(CONSTS.SigAlg))
                throw new Saml20FormatException("The query contains a Signature but no SigAlg.");

            return result;
        }

        #region Query parameters
        private string _message;

        /// <summary>
        /// Returns the message that was contained in the query. Use the <code>IsResponse</code> or the <code>IsRequest</code> property 
        /// to determine the kind of message.
        /// </summary>
        public string Message { get { return _message;  } }

        private string _relaystate;

        /// <summary>
        /// Returns the relaystate that was included with the query. The result will still be encoded according to the 
        /// rules given in section 3.4.4.1 of [SAMLBind], ie. base64-encoded and DEFLATE-compressed. Use the property 
        /// <code>RelayStateDecoded</code> to get the decoded contents of the RelayState parameter.
        /// </summary>
        public string RelayState { get { return _relaystate; } }

        private string _relaystateDecoded;

        /// <summary>
        /// Returns a decoded and decompressed version of the RelayState parameter.
        /// </summary>
        public string RelayStateDecoded
        {
            get
            {
                if (_relaystateDecoded == null)
                    _relaystateDecoded = DeflateDecompress(_relaystate);

                return _relaystateDecoded;                
            }
        }
        

        private string _signatureAlgorithm;

        private string _signature;

        /// <summary>
        /// The signed part of the query is recreated in this string.
        /// </summary>
        private string _signedquery;

        #endregion

        /// <summary>
        /// If the parsed query string contained a SAMLResponse, this variable is set to true.
        /// </summary>
        private bool _isResponse;

        /// <summary>
        /// <code>true</code> if the parsed message contains a response message.
        /// </summary>
        public bool IsResponse { get { return _isResponse;  } }

        /// <summary>
        /// <code>true</code> if the parsed message contains a request message.
        /// </summary>
        public bool IsRequest { get { return !_isResponse;  } }

        /// <summary>
        /// <code>true</code> if the parsed message contains a signature.
        /// </summary>
        public bool IsSigned { get { return _signature != null;  } }

        /// <summary>
        /// Gets the signature value
        /// </summary>
        public string Signature { get { return _signature; } }

        /// <summary>
        /// Gets the signature algorithm.
        /// </summary>
        /// <value>The signature algorithm.</value>
        public string SignatureAlgorithm
        {
            get { return _signatureAlgorithm; }
        }

        /// <summary>
        /// Validates the signature using the public part of the asymmetric key given as parameter.
        /// </summary>
        /// <param name="key"></param>
        /// <returns><code>true</code> if the signature is present and can be verified using the given key.
        /// <code>false</code> if the signature is present, but can't be verified using the given key.</returns>
        /// <exception cref="InvalidOperationException">If the query is not signed, and therefore cannot have its signature verified. Use 
        /// the <code>IsSigned</code> property to check for this situation before calling this method.</exception>
        public bool CheckSignature(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            if (!IsSigned)
                throw new InvalidOperationException("Query is not signed, so there is no signature to verify.");

            var signatureProvider = SignatureProviderFactory.CreateFromHashingAlgorithmSignatureUri(_signatureAlgorithm);
            return signatureProvider.VerifySignature(key, Encoding.UTF8.GetBytes(_signedquery), DecodeSignature());
        }

        /// <summary>
        /// Check the signature of a HTTP-Redirect message using the list of keys. 
        /// </summary>
        /// <param name="keys">A list of KeyDescriptor elements. Probably extracted from the metadata describing the IDP that sent the message.</param>
        /// <returns>True, if one of the given keys was able to verify the signature. False in all other cases.</returns>
        public bool VerifySignature(IEnumerable<KeyDescriptor> keys)
        {
            foreach (KeyDescriptor keyDescriptor in keys)
            {
                KeyInfo ki = (KeyInfo)keyDescriptor.KeyInfo;
                foreach (KeyInfoClause clause in ki)
                {
                    AsymmetricAlgorithm key = XmlSignatureUtils.ExtractKey(clause);
                    if (key != null && CheckSignature(key))
                        return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Decodes the Signature parameter.
        /// </summary>
        private byte[] DecodeSignature()
        {
            if (!IsSigned)
                throw new InvalidOperationException("Query does not contain a signature.");

            return Convert.FromBase64String(_signature);
        }

        /// <summary>
        /// Re-creates the list of parameters that are signed, in order to verify the signature.
        /// </summary>
        private void CreateSignatureSubject(IDictionary<string, string> queryParams)
        {
            StringBuilder signedQuery = new StringBuilder();
            if (IsResponse)
            {
                signedQuery.AppendFormat("{0}=", CONSTS.SAMLResponse);
                signedQuery.Append(queryParams[CONSTS.SAMLResponse]);
            } 
            else
            {
                signedQuery.AppendFormat("{0}=", CONSTS.SAMLRequest);
                signedQuery.Append(queryParams[CONSTS.SAMLRequest]);
            }                
            
            if (_relaystate != null)
                signedQuery.AppendFormat("&{0}=", CONSTS.RelayState).Append(queryParams[CONSTS.RelayState]);

            if (_signature != null)
                signedQuery.AppendFormat("&{0}=", CONSTS.SigAlg).Append(queryParams[CONSTS.SigAlg]);

            _signedquery = signedQuery.ToString();
        }

        /// <summary>
        /// Decodes the message parameter.
        /// </summary>
        private void ReadMessageParameter()
        {
            _message = DeflateDecompress(_message);
        }

        /// <summary>
        /// The largest message accepted after decompression. SAML messages in the Redirect binding are a few kilobytes.
        /// </summary>
        internal const int MaximumInflatedMessageLength = 256 * 1024;

        /// <summary>
        /// Take a Base64-encoded string, decompress the result using the DEFLATE algorithm and return the resulting 
        /// string.
        /// </summary>
        /// <exception cref="Saml20FormatException">If the decompressed message is longer than <see cref="MaximumInflatedMessageLength"/> characters.</exception>
        internal static string DeflateDecompress(string str)
        {
            byte[] encoded = Convert.FromBase64String(str);            
            MemoryStream memoryStream = new MemoryStream(encoded);

            StringBuilder result = new StringBuilder();
            using (DeflateStream stream = new DeflateStream(memoryStream, CompressionMode.Decompress))
            {
                StreamReader reader = new StreamReader(new BufferedStream(stream), Encoding.UTF8);
                char[] buffer = new char[8192];
                int read;
                while ((read = reader.Read(buffer, 0, buffer.Length)) > 0)
                {
                    if (result.Length + read > MaximumInflatedMessageLength)
                        throw new Saml20FormatException($"The decompressed message is longer than {MaximumInflatedMessageLength} characters.");
                    result.Append(buffer, 0, read);
                }
            }
            return result.ToString();
        }

        /// <summary>
        /// Set the parameter fields of the class.
        /// </summary>
        private void SetParam(string key, string value)
        {
            switch(key)
            {
                case CONSTS.SAMLRequest:
                    _isResponse = false;
                    _message = value;
                    return;
                case CONSTS.SAMLResponse:
                    _isResponse = true;
                    _message = value;
                    return;
                case CONSTS.RelayState:
                    _relaystate = value;
                    return;
                case CONSTS.SigAlg:
                    _signatureAlgorithm = value;
                    return;
                case CONSTS.Signature:
                    _signature = value;
                    return;
            }
        }

        /// <summary>
        /// Returns the LogoutRequest string in deserialized form.
        /// </summary>
        /// <returns></returns>
        public LogoutRequest LogoutRequest
        {
            get
            {
                if (!_isResponse)
                    return Serialization.DeserializeFromXmlString<LogoutRequest>(_message);
                else
                    return null;
            }
        }
    }
}