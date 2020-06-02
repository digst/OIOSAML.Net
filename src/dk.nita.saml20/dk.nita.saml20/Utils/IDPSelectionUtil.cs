﻿using System;
using System.Collections.Generic;
using System.Text;
using System.Web;
using dk.nita.saml20.config;
using dk.nita.saml20.protocol;

namespace dk.nita.saml20.Utils
{
    /// <summary>
    /// This delegate is used handling events, where the framework have several configured IDP's to choose from
    /// and needs information on, which one to use.
    /// </summary>
    /// <param name="ep">List of configured endpoints</param>
    /// <returns>The IDPEndPoint for the IDP that should be used for authentication</returns>
    public delegate IDPEndPoint IDPSelectionEventHandler(IDPEndpoints ep);

    /// <summary>
    /// Contains helper functionality for selection of IDP when more than one is configured
    /// </summary>
    public class IDPSelectionUtil
    {
        /// <summary>
        /// The event handler will be called, when no Common Domain Cookie is set, 
        /// no IDPEndPoint is marked as default in the SAML20Federation configuration,
        /// and no idpSelectionUrl is configured.
        /// Make sure that only one eventhandler is added, since only the last result of the eventhandler invocation will be used.
        /// </summary>
        public static event IDPSelectionEventHandler IDPSelectionEvent;

        internal static IDPEndPoint InvokeIDPSelectionEventHandler(IDPEndpoints endpoints)
        {
            if (IDPSelectionEvent != null)
            {
                return IDPSelectionEvent(endpoints);
            }

            return null;
        }

        /// <summary>
        /// Helper method for generating URL to a link, that the user can click to select that particular IDPEndPoint for authorization.
        /// Usually not called directly, but called from IDPEndPoint.GetIDPLoginUrl()
        /// </summary>
        /// <param name="idpId">Id of IDP that an authentication URL is needed for</param>
        /// <param name="forceAuthn">Specifies wether or not the user is forced to login even if the user is already logged in. True means that the user must login into the federation again even if the user was already logged in.</param>
        /// <param name="isPassive">Specifies wether or not the user must be promthed with a login screen at IdP if user is not already logged into the federation. True means that the user must not be promthed with a login screen.</param>
        /// <param name="desiredNSISLevel">Specifies the desired level of assurance.</param>
        /// <param name="desiredProfile">Specifies the desired type of profile (Person or Professional)</param>
        /// <returns>A URL that can be used for logging in at the IDP</returns>
        public static string GetIDPLoginUrl(string idpId, bool forceAuthn, bool isPassive, string desiredNSISLevel, string desiredProfile)
        {
            return string.Format("{0}?{1}={2}&{3}={4}&{5}={6}&{7}={8}&{9}={10}", SAML20FederationConfig.GetConfig().ServiceProvider.SignOnEndpoint.localPath,
                Saml20SignonHandler.IDPChoiceParameterName, HttpUtility.UrlEncode(idpId),
                Saml20SignonHandler.IDPForceAuthn, forceAuthn.ToString(),
                Saml20SignonHandler.IDPIsPassive, isPassive.ToString(),
                Saml20SignonHandler.NSISLevel, desiredNSISLevel,
                Saml20SignonHandler.Profile, desiredProfile);
        }
    }
}
