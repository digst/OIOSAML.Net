using System;
using System.Collections.Generic;
using System.Diagnostics;
using dk.nita.saml20.config;
using Trace=dk.nita.saml20.Utils.Trace;

namespace dk.nita.saml20.Specification
{
    ///<summary>
    /// 
    ///</summary>
    public class SpecificationFactory
    {
        /// <summary>
        /// Gets the certificate specifications.
        /// </summary>
        /// <param name="endpoint">The endpoint.</param>
        /// <returns>A list of certificate validation specifications for this endpoint</returns>
        public static List<ICertificateSpecification> GetCertificateSpecifications(IDPEndPoint endpoint)
        {
            List<ICertificateSpecification> specs = new List<ICertificateSpecification>();

            if(endpoint.CertificateValidation != null && endpoint.CertificateValidation.CertificateValidations != null &&
                endpoint.CertificateValidation.CertificateValidations.Count > 0)
            {
                foreach(CertificateValidationElement elem in endpoint.CertificateValidation.CertificateValidations)
                {
                    specs.Add((ICertificateSpecification) Activator.CreateInstance(Type.GetType(elem.type, true)));
                }
            }

            if(specs.Count == 0)
            {
                //Add default specification
                specs.Add(new DefaultCertificateSpecification());
            }

            return specs;
        }
    }
    
}
