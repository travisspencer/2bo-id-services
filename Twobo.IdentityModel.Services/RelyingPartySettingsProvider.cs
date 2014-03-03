/*
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
 
   RelyingPartySettingsProvider.cs - Demo showing what a the relying party settings 
   provider might do.

 */

using System.Collections.Generic;
using System.Linq;
using Microsoft.IdentityServer.PowerShell.Commands;
using Microsoft.IdentityServer.PowerShell.Resources;

namespace Twobo.IdentityModel.Services
{
    internal class RelyingPartySettingsProvider : IRelyingPartySettingsProvider
    {
        private Dictionary<string, string> notes = new Dictionary<string, string>();

        public IEnumerable<string> GetRequiredClaims(string rpId)
        {
            var notes = GetNotes(rpId);
            string[] requiredClaims = null;

            if (notes != null)
            {
                var noteParts = notes.Split('\\');

                if (noteParts.Length > 1 && !string.IsNullOrWhiteSpace(noteParts[1]))
                {
                    requiredClaims = noteParts[1].Split(',');
                }
            }

            return requiredClaims;
        }

        public IEnumerable<string> GetRequiredCredentials(string rpId)
        {
            var notes = GetNotes(rpId);
            string[] requiredCredentials = null;

            if (notes != null)
            {
                var noteParts = notes.Split('\\');

                requiredCredentials = noteParts[0].Split(',');
            }

            return requiredCredentials;
        }

        private string GetNotes(string rpId)
        {
            if (notes.ContainsKey(rpId) == false)
            {
                var getRelyingPartyTrustCommand = new GetRelyingPartyTrustCommand();

                getRelyingPartyTrustCommand.Identifier = new[] { rpId };

                var results = getRelyingPartyTrustCommand.Invoke<RelyingPartyTrust>();
                var rpt = results.FirstOrDefault<RelyingPartyTrust>();

                if (rpt != null && !string.IsNullOrWhiteSpace(rpt.Notes))
                {
                    notes[rpId] = rpt.Notes;
                }
            }

            return notes[rpId];
        }
    }
}
