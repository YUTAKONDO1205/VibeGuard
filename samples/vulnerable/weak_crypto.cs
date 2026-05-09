// VibeGuard sample: C# weak crypto patterns.
using System;
using System.Security.Cryptography;
using System.Text;

namespace VibeGuardSamples
{
    public static class WeakCrypto
    {
        // VG-CRYPTO-001 — MD5 hash of a password.
        public static string LegacyHash(string password)
        {
            using var hasher = MD5.Create();
            var bytes = hasher.ComputeHash(Encoding.UTF8.GetBytes(password));
            return BitConverter.ToString(bytes);
        }

        // VG-CRYPTO-001 — SHA1 used for "integrity".
        public static byte[] LegacyChecksum(byte[] data)
        {
            using var hasher = SHA1.Create();
            return hasher.ComputeHash(data);
        }

        // VG-CRYPTO-002 — System.Random used to generate a token.
        public static int NewToken()
        {
            var token = new Random().Next();
            return token;
        }
    }
}
