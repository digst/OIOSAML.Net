using System.Text.RegularExpressions;

namespace dk.nita.saml20.Utils
{
    internal static class BrowserSupportUtil
    {
        // With inspiration from https://www.chromium.org/updates/same-site/incompatible-clients
        // Copyright 2019 Google LLC.
        // SPDX-License-Identifier: Apache-2.0
        // Don’t send `SameSite=None` to known incompatible clients.
        public static bool ShouldSendSameSiteNone(string useragent)
        {
            return !IsSameSiteNoneIncompatible(useragent);
        }

        // Classes of browsers known to be incompatible.

        private static bool IsSameSiteNoneIncompatible(string useragent)
        {
            return HasWebKitSameSiteBug(useragent) ||
                DropsUnrecognizedSameSiteCookies(useragent);
        }

        private static bool HasWebKitSameSiteBug(string useragent)
        {
            return IsIosVersion(major: 12, useragent) ||
                   (IsMacosxVersion(major: 10, minor: 14, useragent) &&
                    (IsSafari(useragent) || IsMacEmbeddedBrowser(useragent)));
        }

        private static bool DropsUnrecognizedSameSiteCookies(string useragent)
        {
            if (IsUcBrowser(useragent))
            {
                return !IsUcBrowserVersionAtLeast(major: 12, minor: 13, build: 2, useragent);
            }
            else
            {
                return IsChromiumBased(useragent) &&
                       IsChromiumVersionAtLeast(major: 51, useragent) &&
                       !IsChromiumVersionAtLeast(major: 67, useragent);
            }
        }

        #region Regex parsing of User-Agent string. (See note above!)
        private static bool IsIosVersion(int major, string useragent)
        {
            const string regex = @"\(iP.+; CPU .*OS (\d+)[_\d]*.*\) AppleWebKit\/";
            // Extract digits from first capturing group.
            return Regex.Match(useragent, regex).Groups[1].Value == IntToString(major);
        }

        private static bool IsMacosxVersion(int major, int minor, string useragent)
        {
            const string regex = @"\(Macintosh;.*Mac OS X (\d+)_(\d+)[_\d]*.*\) AppleWebKit\/";
            // Extract digits from first and second capturing groups.
            return (Regex.Match(useragent, regex).Groups[1].Value == IntToString(major)) &&
                   (Regex.Match(useragent, regex).Groups[2].Value == IntToString(minor));
        }

        private static bool IsSafari(string useragent)
        {
            const string safariRegex = @"Version\/.* Safari\/";
            return Regex.IsMatch(useragent, safariRegex) &&
                   !IsChromiumBased(useragent);
        }

        private static bool IsMacEmbeddedBrowser(string useragent)
        {
            const string regex = @"^Mozilla\/[\.\d]+ \(Macintosh;.*Mac OS X [_\d]+\) "
                                 + @"AppleWebKit\/[\.\d]+ \(KHTML, like Gecko\)$";
            return Regex.IsMatch(useragent, regex);
        }

        private static bool IsChromiumBased(string useragent)
        {
            const string regex = @"Chrom(e|ium)";
            return Regex.IsMatch(useragent, regex);
        }

        private static bool IsChromiumVersionAtLeast(int major, string useragent)
        {
            const string regex = @"Chrom[^ \/]+\/(\d+)[\.\d]* ";
            // Extract digits from first capturing group.
            var version = StringToInt(Regex.Match(useragent, regex).Groups[1].Value);
            return version >= major;
        }

        private static bool IsUcBrowser(string useragent)
        {
            const string regex = @"UCBrowser\/";
            return Regex.IsMatch(useragent, regex);
        }

        private static bool IsUcBrowserVersionAtLeast(int major, int minor, int build, string useragent)
        {
            const string regex = @"UCBrowser\/(\d+)\.(\d+)\.(\d+)[\.\d]* ";

            // Extract digits from three capturing groups.
            var majorVersion = StringToInt(Regex.Match(useragent, regex).Groups[1].Value);
            var minorVersion = StringToInt(Regex.Match(useragent, regex).Groups[2].Value);
            var buildVersion = StringToInt(Regex.Match(useragent, regex).Groups[3].Value);

            if (majorVersion != major)
                return majorVersion > major;
            if (minorVersion != minor)
                return minorVersion > minor;

            return buildVersion >= build;
        }

        private static int StringToInt(string intString)
        {
            return int.Parse(intString);
        }

        private static string IntToString(int number)
        {
            return number.ToString();
        }
        #endregion
    }
}
