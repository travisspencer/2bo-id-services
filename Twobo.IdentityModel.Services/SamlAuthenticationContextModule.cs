﻿/*
   Copyright (C) 2014 Twobo Technologies AB

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 
   SamlAuthenticationContextModule.cs - ASP.NET HTTP module that gets RP-specific 
   settings (e.g., required credentials) and updates ADFS' SAML authentication
   request to include that data (as appropriate).

 */

using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Caching;
using System.Xml;

namespace Twobo.IdentityModel.Services
{
    public class SamlAuthenticationContextModule : IHttpModule
    {
        private IRelyingPartySettingsProvider relyingPartySettingsProvider;

        public void Dispose() { }

        public void Init(HttpApplication application)
        {
            application.EndRequest += new EventHandler(this.Application_EndRequest);
        }

        protected virtual IRelyingPartySettingsProvider RelyingPartySettingsProvider
        {
            get 
            {
                if (relyingPartySettingsProvider == null)
                {
                    var typeName = ConfigurationManager.AppSettings["RelyingPartySettingsProvider"];

                    if (string.IsNullOrWhiteSpace(typeName))
                    {
                        return new RelyingPartySettingsProvider();
                    }
                    else
                    {
                        var type = Type.GetType(typeName);

                        return (IRelyingPartySettingsProvider)Activator.CreateInstance(type);
                    }
                }

                return relyingPartySettingsProvider;
            }
        }

        private void Application_EndRequest(Object source, EventArgs e)
        {
            var application = (HttpApplication)source;
            var context = application.Context;

            if (context.Response.StatusCode == 302)
            {
                var rpId = GetRelyingPartyId(context.Request);

                if (!string.IsNullOrWhiteSpace(rpId))
                {
                    var rpCredentials = GetRequiredCredentialsForRelyingParty(context.Cache, rpId);

                    if (rpCredentials != null && rpCredentials.Count() > 0)
                    {
                        var redirectLocation = new Uri(context.Response.RedirectLocation);
                        var query = HttpUtility.ParseQueryString(redirectLocation.Query);
                        var newRedirectLocaitonBuilder = new UriBuilder(redirectLocation);

                        query["SAMLRequest"] = AddAuthenticationContext(rpCredentials, query["SAMLRequest"]);

                        newRedirectLocaitonBuilder.Query = query.ToString();

                        context.Response.RedirectLocation = newRedirectLocaitonBuilder.ToString();
                    }
                }
            }
        }

        private string AddAuthenticationContext(IEnumerable<string> rpCredentials, string originalEncodedSamlRequest)
        {
            var decodedSamlMessage = DecodeSamlRedirectMessage(originalEncodedSamlRequest);
            var doc = new XmlDocument();

            doc.LoadXml(decodedSamlMessage);

            var requestedAuthnContextElement = doc.CreateElement("RequestedAuthnContext", "urn:oasis:names:tc:SAML:2.0:protocol");

            // NOTE: Exact comparison of the authN context is the default and that's what 
            // we want, so it's not explicitly added.

            foreach (var credential in rpCredentials)
            {
                var authnContextClassRefElement = doc.CreateElement("AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:assertion");

                authnContextClassRefElement.InnerText = credential;

                requestedAuthnContextElement.AppendChild(authnContextClassRefElement);
            }

            // NOTE: Where we insert the new request authN context element matters. The schema defines 
            // a sequence of child elements for the AuthnRequestType. They are Subject, NameIDPolicy, 
            // Conditions, RequestedAuthnContext, Scoping.
            var scopingElement = doc.DocumentElement["Scoping", "urn:oasis:names:tc:SAML:2.0:protocol"];

            if (scopingElement == null)
            {
                doc.DocumentElement.AppendChild(requestedAuthnContextElement);
            }
            else
            {
                doc.DocumentElement.InsertBefore(scopingElement, requestedAuthnContextElement);
            }

            // Note: We're assuming the request wasn't signed, so we're not re-signing it. This is a safe assumping when 
            // using the redirect binding (see note on line 580 and 581 of the SAML 2.0 binding spec). If it were signed 
            // or if this method were used when sending the authN request over the POST binding, we could re-sign it. 
            // Just a matter of code ;-)

            if (doc.DocumentElement["Signature", "http://www.w3.org/2000/09/xmldsig#"] != null)
            {
                throw new NotImplementedException("Re-signing of an authentication request is not currently supported.");
            }

            var updatedEncodedSamlMessage = EncodeSamlRedirectMessage(doc);

            return updatedEncodedSamlMessage;
        }

        // NOTE: The implementation of this function is based on code from ForgeRock (licesed under the CDDLv1). See
        // https://svn.forgerock.org/openam/branches/opensso_build9_branch/opensso/products/federation/library/csharpsource/Fedlet/Fedlet/source/Saml2/Saml2Utils.cs
        private string EncodeSamlRedirectMessage(XmlDocument unencodedSamlRequest)
        {
            var buffer = Encoding.UTF8.GetBytes(unencodedSamlRequest.OuterXml);
            
            using (var memoryStream = new MemoryStream())
            using (var compressedStream = new DeflateStream(memoryStream, CompressionMode.Compress, true))
            {
                compressedStream.Write(buffer, 0, buffer.Length);
                compressedStream.Close();

                memoryStream.Position = 0;

                var compressedBuffer = new byte[memoryStream.Length];

                memoryStream.Read(compressedBuffer, 0, compressedBuffer.Length);

                return Convert.ToBase64String(compressedBuffer);
            }            
        }

        private IEnumerable<string> GetRequiredCredentialsForRelyingParty(Cache cache, string rpId)
        {
            var key = rpId + "_Credentials";
            var rpCredentials = cache[key] as IEnumerable<string>;

            if (rpCredentials == null)
            {
                rpCredentials = RelyingPartySettingsProvider.GetRequiredCredentials(rpId);
                cache[key] = rpCredentials;
            }

            return rpCredentials;
        }

        private string GetRelyingPartyId(HttpRequest request)
        {
            var id = GetRelyingPartyIdIfWSFederation(request);

            if (id == null)
            {
                id = GetRelyingPartyIdIfSamlRedirect(request);

                if (id == null)
                {
                    id = GetRelyingPartyIdIfSamlPost(request);

                    if (id == null)
                    {
                        throw new InvalidOperationException("The request did not contain a WS-Federation " +
                            "or SAML authentication request");
                    }
                }
            }

            return id;
        }

        private string GetRelyingPartyIdIfWSFederation(HttpRequest request)
        {
            return HttpUtility.ParseQueryString(request.Url.Query).Get("wtrealm");
        }

        private string GetRelyingPartyIdIfSamlRedirect(HttpRequest request)
        {
            var encodedSamlRequest = HttpUtility.ParseQueryString(request.Url.Query).Get("SAMLRequest");
            string id = null;

            if (!string.IsNullOrWhiteSpace(encodedSamlRequest))
            {
                var decodedSamlMessage = DecodeSamlRedirectMessage(encodedSamlRequest);

                id = GetRelyingPartyIdFromDecodedSamlRequest(decodedSamlMessage);
            }

            return id;
        }

        private string DecodeSamlRedirectMessage(string encodedSamlRequest)
        {
            var input = Convert.FromBase64String(encodedSamlRequest);

            using (var output = new MemoryStream())
            {
                using (var compressStream = new MemoryStream(input))
                {
                    using (var decompressor = new DeflateStream(compressStream, CompressionMode.Decompress))
                    {
                        decompressor.CopyTo(output);
                    }
                }

                output.Position = 0;

                return Encoding.UTF8.GetString(output.ToArray());
            }
        }

        private string GetRelyingPartyIdIfSamlPost(HttpRequest request)
        {
            string id = null;
            var msisSamlRequestParam = request.Params["MSISSamlRequest"];

            if (!string.IsNullOrWhiteSpace(msisSamlRequestParam))
            {
                var encodedMsisSamlRequest = msisSamlRequestParam.Split(',').Last();
                var decodedMsisSamlRequest = Encoding.UTF8.GetString(Convert.FromBase64String(encodedMsisSamlRequest));
                var startIndex = decodedMsisSamlRequest.IndexOf("SAMLRequest=");

                if (startIndex != -1)
                {
                    startIndex += "SAMLRequest=".Length;

                    string encodedSamlRequest;
                    var endIndex = decodedMsisSamlRequest.IndexOf("\\", startIndex);

                    if (endIndex == -1)
                    {
                        encodedSamlRequest = decodedMsisSamlRequest.Substring(startIndex);
                    }
                    else
                    {
                        encodedSamlRequest = decodedMsisSamlRequest.Substring(startIndex, endIndex - startIndex);
                    }

                    var decodedSamlRequest = Encoding.UTF8.GetString(Convert.FromBase64String(
                        HttpUtility.UrlDecode(encodedSamlRequest)));

                    id = GetRelyingPartyIdFromDecodedSamlRequest(decodedSamlRequest);
                }
            }

            return id;
        }

        private string GetRelyingPartyIdFromDecodedSamlRequest(string decodedSamlRequest)
        {
            var doc = new XmlDocument();
            string id = null;

            doc.LoadXml(decodedSamlRequest);

            var audienceList = doc.GetElementsByTagName("Audience", "urn:oasis:names:tc:SAML:2.0:assertion");

            if (audienceList.Count > 0 && audienceList[0] is XmlElement)
            {
                id = ((XmlElement)audienceList[0]).InnerText;
            }
            else
            {
                var issuerList = doc.GetElementsByTagName("Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");

                if (issuerList.Count > 0 && issuerList[0] is XmlElement)
                {
                    id = ((XmlElement)issuerList[0]).InnerText;
                }
            }

            return id;
        }        
    }
}