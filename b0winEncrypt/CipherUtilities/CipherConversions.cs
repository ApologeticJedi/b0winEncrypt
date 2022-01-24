using System;
using System.Linq;
using System.Text;

namespace b0winEncrypt.CipherUtilities
{
    public static class CipherConversions
    {
        /// <summary>
        /// Returns the index 0 byte of the word
        /// </summary>
        /// <param name="word">the word</param>
        /// <returns></returns>
        public static byte WordByte0(uint word)
        {
            return (byte)(word / 256 / 256 / 256 % 256);
        }

        /// <summary>
        /// Returns the index 1 byte of the word
        /// </summary>
        /// <param name="word">the word</param>
        /// <returns></returns>
        public static byte WordByte1(uint word)
        {
            return (byte)(word / 256 / 256 % 256);
        }

        /// <summary>
        /// Returns the index 2 byte of the word
        /// </summary>
        /// <param name="word">the word</param>
        /// <returns></returns>
        public static byte WordByte2(uint word)
        {
            return (byte)(word / 256 % 256);
        }

        /// <summary>
        /// Returns the index 3 byte of the word
        /// </summary>
        /// <param name="word">the word</param>
        /// <returns></returns>
        public static byte WordByte3(uint word)
        {
            return (byte)(word % 256);
        }

        /// <summary>
        /// Converst a Byte to Hex string
        /// </summary>
        /// <param name="bytes">array of bytes to convert</param>
        /// <returns></returns>
        public static string ByteToHex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "");
        }

        /// <summary>
        /// Converts a string of hex to a byte array
        /// </summary>
        /// <param name="hexString">hex string to convert</param>
        /// <returns></returns>
        public static byte[] HexToByte(string hexString)
        {
            return Enumerable.Range(0, hexString.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hexString.Substring(x, 2), 16))
                             .ToArray();
        }
        
    }
}
