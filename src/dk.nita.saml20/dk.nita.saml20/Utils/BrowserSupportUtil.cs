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
            return isIosVersion(major: 12, useragent) ||
                   (isMacosxVersion(major: 10, minor: 14, useragent) &&
                    (isSafari(useragent) || isMacEmbeddedBrowser(useragent)));
        }

        private static bool DropsUnrecognizedSameSiteCookies(string useragent)
        {
            if (isUcBrowser(useragent))
            {
                return !isUcBrowserVersionAtLeast(major: 12, minor: 13, build: 2, useragent);
            }
            else
            {
                return isChromiumBased(useragent) &&
                       isChromiumVersionAtLeast(major: 51, useragent) &&
                       !isChromiumVersionAtLeast(major: 67, useragent);
            }
        }

        #region Regex parsing of User-Agent string. (See note above!)
        private static bool isIosVersion(int major, string useragent)
        {
            string regex = @"\(iP.+; CPU .*OS (\d+)[_\d]*.*\) AppleWebKit\/";
            // Extract digits from first capturing group.
            return Regex.Match(useragent, regex).Value == intToString(major);
        }

        private static bool isMacosxVersion(int major, int minor, string useragent)
        {
            string regex = @"\(Macintosh;.*Mac OS X (\d+)_(\d+)[_\d]*.*\) AppleWebKit\/";
            // Extract digits from first and second capturing groups.
            return (Regex.Match(useragent, regex).Groups[1].Value == intToString(major)) &&
                   (Regex.Match(useragent, regex).Groups[2].Value == intToString(minor));
        }

        private static bool isSafari(string useragent)
        {
            string safari_regex = @"Version\/.* Safari\/";
            return Regex.IsMatch(useragent, safari_regex) &&
                !isChromiumBased(useragent);
        }

        private static bool isMacEmbeddedBrowser(string useragent)
        {
            string regex = @"^Mozilla\/[\.\d]+ \(Macintosh;.*Mac OS X [_\d]+\) "
                             + @"AppleWebKit\/[\.\d]+ \(KHTML, like Gecko\)$";
            return Regex.IsMatch(useragent, regex);
        }

        private static bool isChromiumBased(string useragent)
        {
            string regex = @"Chrom(e|ium)";
            return Regex.IsMatch(useragent, regex);
        }

        private static bool isChromiumVersionAtLeast(int major, string useragent)
        {
            string regex = @"Chrom[^ \/]+\/(\d+)[\.\d]* ";
            // Extract digits from first capturing group.
            int version = stringToInt(Regex.Match(useragent, regex).Groups[1].Value);
            return version >= major;
        }

        private static bool isUcBrowser(string useragent)
        {
            string regex = @"UCBrowser\/";
            return Regex.IsMatch(useragent, regex);
        }

        private static bool isUcBrowserVersionAtLeast(int major, int minor, int build, string useragent)
        {
            string regex = @"UCBrowser\/(\d+)\.(\d+)\.(\d+)[\.\d]* ";

            // Extract digits from three capturing groups.
            int major_version = stringToInt(Regex.Match(useragent, regex).Groups[1].Value);
            int minor_version = stringToInt(Regex.Match(useragent, regex).Groups[2].Value);
            int build_version = stringToInt(Regex.Match(useragent, regex).Groups[3].Value);

            if (major_version != major)
                return major_version > major;
            if (minor_version != minor)
                return minor_version > minor;

            return build_version >= build;
        }

        private static int stringToInt(string intString)
        {
            return int.Parse(intString);
        }

        private static string intToString(int number)
        {
            return number.ToString();
        }
        #endregion
    }
}
