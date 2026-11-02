# OIO SAML 3

## 3.1.0

A security and maintenance release of dk.nita.saml20 before it is replaced by [DK.Gov.Oio.Saml](https://github.com/digst/oiosaml-net). It brings the library in line with the OIOSAML Web SSO Profile on the points below and lets NemLog-in change its signing certificate without an outage for service providers. Read **Upgrading from 3.0.x** before upgrading: some input that 3.0.x accepted is now refused.

### Login
- The assertion must answer the AuthnRequest this service provider sent (signed `InResponseTo`), be addressed to one of its assertion consumer services (`Recipient`), come from the IdP the request was sent to, be encrypted, and is accepted only once (REF-79).
- The minimum NSIS level of assurance can only be raised by a request parameter, never lowered (REF-77).
- The session id changes at login (REF-81).
- A login ends after `MaximumSessionLength` minutes (default 480) from the authentication at the IdP, or at the IdP's `SessionNotOnOrAfter`; expired sessions are no longer read or extended by the session stores. `Saml20Identity.IsInitialized()` requires a completed login, and the Forms ticket issued at login is tied to the OIOSAML session (REF-97).

### Single logout
- IdP logout messages are checked fully on every binding: signature with the IdP's signing keys, `Destination`, `IssueInstant`, `NotOnOrAfter`, each ID once, and through the browser the NameID and SessionIndex of the session (REF-77, REF-94).
- A logout started by the service provider ends the local session before the user is sent to the IdP; the LogoutResponse must answer that request (REF-94).
- An IdP LogoutRequest delivered by artifact now logs the user out (REF-94).

### Signatures, encryption and metadata
- Only the algorithms of [OIO-ALG-01] are accepted: RSA-SHA256 with SHA-256 digests, exclusive canonicalization, RSA-OAEP key transport and AES-CBC. DTDs are refused in received XML, and the size of Redirect-binding messages is limited (REF-82).
- IdP metadata files are reloaded safely when they change, files with the same `entityID` are combined, and a `KeyDescriptor` without `use` counts for signing: NemLog-in can publish a new signing certificate next to the old one (REF-80). The endpoint lists are built when the metadata is read (REF-96, GitHub #72).
- The service provider's own certificate is looked up by its validity period, cached for ten minutes and used for every message, including Redirect AuthnRequests; CNG keys are supported (REF-13, REF-92, REF-96, GitHub #83).

### Logging and errors
- Audit entries identify SAML messages by their identifiers instead of containing them; the session id is logged as a hash; full messages are traced only at `Verbose`, and decrypted assertions never (REF-93).
- The error page shows encoded text without exception details and answers 400 or 500 (REF-95).

### Other
- Non-metadata files in the metadata directory are ignored (GitHub #25); a clear error for a misspelt default IdP (#24); `fullName` attribute name (#75) (REF-11).
- New demo SP certificate, valid to 2029; the demo runs on `https://localhost:20002` (REF-13, REF-79, GitHub #77).
- log4net 3.5.0 in dk.nita.saml20.ext.audit.log4net.
- CI on GitHub Actions; releases are published from a tag by the Release workflow (REF-10, REF-76, REF-98).

### Upgrading from 3.0.x
- **Algorithms:** assertions and messages signed with SHA-1, or encrypted with RSA-1.5 or 3DES, are refused, and `SHA1`/`SHA512` are refused as configured signing algorithms. NemLog-in uses the allowed algorithms.
- **Plain assertions:** an unencrypted assertion is refused. An inbound SOAP `ArtifactResponse` is refused.
- **Configuration that is refused at start-up:** `omitAssertionSignatureCheck="true"`, a `CertificateValidation` type that can't be loaded, an invalid `MinimumNsisLoa`.
- **`IAuthnRequestAppender`:** an appender that sets `AssertionConsumerServiceURL` or `AssertionConsumerServiceIndex` must point at one of the service provider's configured ACS URLs; a response to any other URL is refused.
- **During the upgrade:** logins in progress while the new version is deployed fail once; the user logs in again.
- **IdP keys:** keys given only as `KeyValue` in IdP metadata (without a certificate) are no longer trusted.
- **SP certificate:** `validOnly` on `SigningCertificate` has no effect; the SP doesn't check the chain or revocation of its own certificate. The metadata lists every unexpired certificate.
- **Logout actions:** on a logout started by the service provider, configured logout actions run before the user is sent to the IdP, not when the LogoutResponse returns; only `RedirectAction` waits for the response.
- **Sessions:** logins end after at most 8 hours by default (`<MaximumSessionLength>` in the `Federation` section). `IsInitialized()` is false while the AuthnRequest is pending. The Forms ticket's `UserData` is set by the library. Sessions stored by 3.0.x keep working until they time out.
- **Logging:** a custom `IAuditLogger` receives a hashed session id and no message XML. To see full messages while troubleshooting, set the `dk.nita.saml20` trace source to `Verbose`.
- **Error page:** answers 400 or 500 instead of 200; `ErrorPage.OverrideConfig` is ignored; `BindingUtility.ValidateConfiguration` returns plain text.
- **log4net:** dk.nita.saml20.ext.audit.log4net now depends on log4net 3.5.0 (from 2.0.x); add a binding redirect if the application uses another log4net version.

## 3.0.4
- NLRFIM-169: Support AppSwitch extension on AuthnRequest in dotNET OIO SAML 3

## 3.0.2
- NLRFIM-157: Added configurable IAuthnRequestAppender to allow additional modifications by the user of the package just before the AuthnRequest is signed and transferred.

## 3.0.1
- NLRFIM-99: Fixing use of regular expression match for iOS user agent in BrowserSupportUtil
- NLRFIM-111: Updated documentation for configuration of signing certificates in configuration file
- NLRFIM-119: Minor fixes
  - Add EncryptionMethod URLs for RSA-OAEP-MGF1P and AES256-CBC as default in metadata
  - Don't add NSIS LoA Low in IdentityProviderDemo when old AssuranceLevel is used to Assertion
  - Serialize comparison attribute correctly in AuthnRequest
- NLRFIM-117: Update text used WebSiteDemo when request a professional identity
- NLRFIM-118: Update XML namespace for OIO BPP to http://digst.dk/oiosaml/basic_privilege_profile cf. profile version 1.2
- NLRFIM-127: Protect against cross-site scripting for NSIS LoA and profile request parameters in Saml20SignonHandler.cs

## 3.0.0
First official release OIO SAML 3.

# OIO SAML 2

## 2.0.6
Stable OIO SAML 2 reference implementation.
