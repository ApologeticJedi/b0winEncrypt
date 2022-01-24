using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;


/****************************************************************************
 *                                                                          *
 *  NAME:     b0Cipher.cs                                                   *
 *  AUTHOR:   Brian D. Cross (bdcross/b0c017x)                              *
 *                                                                          *
 *  DESCRIPTION:                                                            *
 *    Less simplistic encryption algorythm. Credit to Bruce Schneier whose  *
 *    "Applied Cryptography" book I purchased in the late 90s and inspired  *
 *    my love of puzzles. This is obviously based on his early Blowfish     *
 *    algorythms found in the back of that book with slight modifcations to *
 *    sequencing.                                                           *
 ****************************************************************************
 *  REVISION HISTORY                                                        *
 *    DATE        USER      DESC                                            *
 *    2019-05-24  b0c017x   Creation.                                       *
 ****************************************************************************/


namespace b0winEncrypt.CipherUtilities
{
    public class B0Cipher
    {

        #region fields/properties
        // Key
        private byte[] key;

        // Initialization Vector (IV)
        RNGCryptoServiceProvider __ivRandomizer;
        private byte[] __initVector;
        public bool IVSet { get; set; }

        // Encapsulation of InitVector
        public byte[] InitVector
        {
            get { return __initVector;  }
            set { __initVector = value; IVSet = true; }
        }
        
        // Blocks and half blocks
        private uint[] __pblock;
        private uint[] __s0block;
        private uint[] __s1block;
        private uint[] __s2block;
        private uint[] __s3block;
        
        private uint __lefthblock;
        private uint __righthblock;

        // Converter for javascript non standard.
        public bool NonStandardMethod { get; set; }

        #endregion

        #region .ctor

        public B0Cipher(string passPhrase)
        {
            __ivRandomizer = new RNGCryptoServiceProvider();
            SetupKey(CipherConversions.HexToByte(CreateKeyFromPassPhrase(passPhrase)));
        }

        #endregion

        #region "public methods"

        public void EncryptFile(string infile, string outfile)
        {
            if (!IVSet)
                SetRandomIV();
            using (FileStream outStream = new FileStream(outfile, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite))
            {
                outStream.Write(__initVector, 0, __initVector.Length);
                using (FileStream inStream = new FileStream(infile, FileMode.Open, FileAccess.Read))
                {
                    byte[] buffer = new byte[inStream.Length + (inStream.Length % 8)];
                    inStream.Read(buffer, 0, buffer.Length);
                    byte[] transform = CipherBlockChain(buffer, false);
                    outStream.Write(transform, 0, transform.Length);
                }
            }
        }

        public void DecryptFile(string cipherFile, string outfile)
        {
            __initVector = new byte[8];
            using (FileStream inStream = new FileStream(cipherFile, FileMode.Open, FileAccess.Read))
            using (FileStream outStream = new FileStream(outfile, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite))
            {
                byte[] buffer = new byte[inStream.Length-__initVector.Length];
                inStream.Read(__initVector, 0, __initVector.Length);
                inStream.Read(buffer, 0, buffer.Length);
                byte[] transform = CipherBlockChain(buffer, true);
                outStream.Write(transform, 0, transform.Length);
            }
            
        }

        public string EncryptString(string plainText)
        {
            if (!IVSet)
                SetRandomIV();
            return CipherConversions.ByteToHex(__initVector) + CipherConversions.ByteToHex(CipherBlockChain(Encoding.ASCII.GetBytes(plainText),false));
        }

        public string DecryptString(string ct)
        {
            InitVector = CipherConversions.HexToByte(ct.Substring(0, 16));
            return Encoding.ASCII.GetString(CipherBlockChain(CipherConversions.HexToByte(ct.Substring(16)),true)).Replace("\0", "");
        }

        #endregion

        #region private methods

        private string ReverseString(string s)
        {
            char[] charArray = s.ToCharArray();
            Array.Reverse(charArray);
            return new string(charArray);
        }

        private string ForceKeyto1024bits(string hexString)
        {
            StringBuilder sb = new StringBuilder(hexString);
            while (sb.Length < 256)
            {
                for (int i = 0; i < hexString.Length / 2; i++)
                {
                    int checkKey = Convert.ToInt32(hexString.Substring(i * 2, 2), 16);
                    if (checkKey % 5 == 0)
                        sb.Append(checkKey + hexString);
                    else if (checkKey % 3 == 0)
                        sb.Append("BDC");                       // Signature BDC : 101111011100
                    else if (checkKey % 2 == 0)
                        sb.Append(ReverseString(hexString));
                    else
                        sb.Append(hexString);
                }
            }
            return sb.ToString().Substring(0, 256);
        }

        private string CreateKeyFromPassPhrase(string passPhrase)
        {
            return ForceKeyto1024bits(CipherConversions.ByteToHex(Encoding.Default.GetBytes(passPhrase)));
        }

        private byte[] SetRandomIV()
        {
            __initVector = new byte[8];
            __ivRandomizer.GetBytes(__initVector);
            IVSet = true;
            return __initVector;
        }

        private void InitializeBlocks()
        {
            __pblock = CipherConstants.Initialize_PBlock();
            __s0block = CipherConstants.Initialize_S0Block();
            __s1block = CipherConstants.Initialize_S1Block();
            __s2block = CipherConstants.Initialize_S2Block();
            __s3block = CipherConstants.Initialize_S3Block();
        }

        private int GetPaddedLength(byte[] text)
        {
            return (text.Length % 8 == 0 ? text.Length : text.Length + 8 - (text.Length % 8));
        }

        private void SetupKey(byte[] cipherKey)
        {
            InitializeBlocks();
            key = new byte[cipherKey.Length]; // 448 bits
            Buffer.BlockCopy(cipherKey, 0, key, 0, cipherKey.Length);

            // Prepare the Blocks
            for (int i = 0, j = 0; i < 18; i++)
            {
                __pblock[i] ^= (uint)(((key[j % cipherKey.Length] * 256 + key[(j + 1) % cipherKey.Length]) * 256 + key[(j + 2) % cipherKey.Length]) * 256 + key[(j + 3) % cipherKey.Length]); ;
                j = (j + 4) % cipherKey.Length;
            }
            __lefthblock = 0;
            __righthblock = 0;
            for (int p_i = 0; p_i < 18; p_i += 2)
            {
                Encipher();
                __pblock[p_i] = __lefthblock;
                __pblock[p_i + 1] = __righthblock;
            }

            for (int s0_i = 0; s0_i < 256; s0_i += 2)
            {
                Encipher();
                __s0block[s0_i] = __lefthblock;
                __s0block[s0_i + 1] = __righthblock;
            }
            for (int s1_i = 0; s1_i < 256; s1_i += 2)
            {
                Encipher();
                __s1block[s1_i] = __lefthblock;
                __s1block[s1_i + 1] = __righthblock;
            }
            for (int s2_i = 0; s2_i < 256; s2_i += 2)
            {
                Encipher();
                __s2block[s2_i] = __lefthblock;
                __s2block[s2_i + 1] = __righthblock;
            }
            for (int s3_i = 0; s3_i < 256; s3_i += 2)
            {
                Encipher();
                __s3block[s3_i] = __lefthblock;
                __s3block[s3_i + 1] = __righthblock;
            }
        }

        private byte[] CipherBlockChain(byte[] text, bool decrypt)
        {
            byte[] plainText = new byte[GetPaddedLength(text)];
            Buffer.BlockCopy(text, 0, plainText, 0, text.Length);
            byte[] block = new byte[8];
            byte[] preblock = new byte[8];
            byte[] iv = new byte[8];
            Buffer.BlockCopy(__initVector, 0, iv, 0, 8);
            for (int i = 0; i < plainText.Length; i += 8)
            {
                Buffer.BlockCopy(plainText, i, block, 0, 8);
                if (decrypt)
                {
                    Buffer.BlockCopy(block, 0, preblock, 0, 8);
                    DecryptBlock(ref block);
                    XorBlockAndIV(ref block, iv);
                    Buffer.BlockCopy(preblock, 0, iv, 0, 8);
                }
                else
                {
                    XorBlockAndIV(ref block, iv);
                    EncryptBlock(ref block);
                    Buffer.BlockCopy(block, 0, iv, 0, 8);
                }
                Buffer.BlockCopy(block, 0, plainText, i, 8);
            }
            return plainText;
        }

        private void XorBlockAndIV(ref byte[] block, byte[] iv)
        {
            for (int i = 0; i < block.Length; i++)
            {
                block[i] ^= iv[i];
            }
        }

        private void EncryptBlock(ref byte[] block)
        {
            SplitBlock(block);
            Encipher();
            JoinBlock(ref block);
        }

        private void DecryptBlock(ref byte[] block)
        {
            SplitBlock(block);
            Decipher();
            JoinBlock(ref block);
        }

        private void SplitBlock(byte[] block)
        {
            byte[] block1 = new byte[4];
            byte[] block2 = new byte[4];
            Buffer.BlockCopy(block, 0, block1, 0, 4);
            Buffer.BlockCopy(block, 4, block2, 0, 4);
            //split the block
            if (NonStandardMethod)
            {
                __righthblock = BitConverter.ToUInt32(block1, 0);
                __lefthblock = BitConverter.ToUInt32(block2, 0);
            }
            else
            {
                //ToUInt32 requires the bytes in reverse order
                Array.Reverse(block1);
                Array.Reverse(block2);
                __lefthblock = BitConverter.ToUInt32(block1, 0);
                __righthblock = BitConverter.ToUInt32(block2, 0);
            }
        }

        private void JoinBlock(ref byte[] block)
        {
            byte[] block1 = new byte[4];
            byte[] block2 = new byte[4];
            if (NonStandardMethod)
            {
                block1 = BitConverter.GetBytes(__righthblock);
                block2 = BitConverter.GetBytes(__lefthblock);
            }
            else
            {
                block1 = BitConverter.GetBytes(__lefthblock);
                block2 = BitConverter.GetBytes(__righthblock);

                //GetBytes returns the bytes in reverse order
                Array.Reverse(block1);
                Array.Reverse(block2);
            }
            //join the block
            Buffer.BlockCopy(block1, 0, block, 0, 4);
            Buffer.BlockCopy(block2, 0, block, 4, 4);
        }

        private void Encipher()
        {
            __lefthblock ^= __pblock[0];
            for (uint i = 0; i < CipherConstants.ROUNDS; i += 2)
            {
                __righthblock = CipherRound(__righthblock, __lefthblock, i + 1);
                __lefthblock = CipherRound(__lefthblock, __righthblock, i + 2);
            }
            __righthblock = __righthblock ^ __pblock[17];

            //swap the blocks
            uint swap = __lefthblock;
            __lefthblock = __righthblock;
            __righthblock = swap;
        }

        private void Decipher()
        {
            __lefthblock ^= __pblock[17];
            for (uint i = 16; i > 0; i -= 2)
            {
                __righthblock = CipherRound(__righthblock, __lefthblock, i);
                __lefthblock = CipherRound(__lefthblock, __righthblock, i - 1);
            }
            __righthblock = __righthblock ^ __pblock[0];

            //swap the blocks
            uint swap = __lefthblock;
            __lefthblock = __righthblock;
            __righthblock = swap;
        }

        private uint CipherRound(uint a, uint b, uint n)
        {
            uint x1 = (__s0block[CipherConversions.WordByte0(b)] + __s1block[CipherConversions.WordByte1(b)]) ^ __s2block[CipherConversions.WordByte2(b)];
            uint x2 = x1 + __s3block[CipherConversions.WordByte3(b)];
            uint x3 = x2 ^ __pblock[n];
            return x3 ^ a;
        }

        #endregion
    }
}
