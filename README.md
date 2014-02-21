# Twobo Identity Model Services

_An HTTP module for use with ADFS which adds Relying-Party-specific credential requirements to ADFS' SAML authentication requests_

# Brief Overview

ADFS lacks a way of specifying on a cases-by-case basis which types of credentials are required by a trusted Relying Party (RP). This can be problematic when ADFS is being used as a passive RP- or FP-STS. When ADFS receives SAML or WS-Federation messages from such downstream RPs that do not specify their authentication requirements, this limitation of ADFS can make it impossible for an upstream SAML Identity Provider (IdP) to authenticate the user at a sufficient level. This can be handled at the RP or in ADFS with an authorization rule, but this results in a poor user experiece. 

This HTTP module can be used with ADFS to get information about the credentials that any particular RP may have. These RP-specific credentials are added to the SAML authentication requests that are sent to the upstream IdP. These are conveyed in `AuthnContextClassRef` elements, allowing the IdP to receive these requirements in a standards-based manner.

This module does this by subscribing to the `EndRequest` event defined by the `IHttpModule`. This causes it to fire with each request made to ADFS. It should be the last module to run in the ASP.NET processing pipeline, allowing it to alter the response created by ADFS. If ASDFS' response has a `302` status code and if the module can parse the RP ID out of the request, it will determine the RP's credential requirements and alter the response accordingly.

To this end, the module uses a provider that queries some sort of data source. This provider may look in ADFS' `web.config` file, ADFS' database, or some other repository. Which provider is used can be configured using the `RelyingPartySettingsProvider` app setting in ADFS's `web.config` file. Alternatively, you can subclass the module and override the `RelyingPartySettingsProvider` property or just rewrite the `RelyingPartySettingsProvider` class which does nothing useful anyway. (Little bit of over-engineering going on today!)

When the HTTP module sees that ADFS is redirecting the end user, it is assumed that it is using the SAML protocol's redirect binding to forward the authentication request to an upstream IdP. The module parses the associated request to determine the RP ID by:

1. Checking for a `wtrealm` in the query string. This is the case when the downstream RP is using WS-Federation to integrate with ADFS.
2. Checking for a `SAMLRequest` in the query string. This is the case when the downstream SP is using the SAML redirect binding to communicate with ADFS.
3. Check the `MSISSamlRequest` slot of the request object's `Params` dictionary. If this is not null, it is because ADFS has placed a SAML authentication request send from a downstream SP using the POST binding.

If the RP ID can be found, the settings provider is quired for the required credentials that subjects should use when authenticating to the upstream IdP. 

> NOTE: The incoming request is not checked to see if it contains any information about the required authentication and if that is in the list provided. It should, but that's for another day.

If it returns one or more required credentials, the redirect location set by ADFS is interrogated. This contains the SAML authentication request that ADFS has created. This has a lot of important information, such as the assertion ID, that must not be altered. This SAML authentication request is not signed, however, so we can change some parts of it. The credentials provided are then inserted into this request as `AuthnContextClassRef`elements. After this, the altered message is re-encoded and put into the `RedirectLocation` of the response. Consequently, ADFS will send it on to the upsteam IdP. When ADFS receives the response, it will handle it as if the alteration never took place.

If you have questions, issues or need more info, open an ticket or send a pull request.