using b0winEncrypt.CipherUtilities;
using b0winEncrypt.Utilities;
using System;

/* 
 * TODO: Need to check source file exists -- error if file does not exist
 *       Need to check destination file exists -- prompt for overwrite if it does
 */  
     

namespace b0winEncrypt
{
    class b0winEncrypt
    {
        public static string Passphrase
        {
            get
            {
                return (String.IsNullOrEmpty(ArgsManager.Passphrase))
                    ? ConsoleUtilities.GetPassPhrase(Encrypt)
                    : ArgsManager.Passphrase;
            }
        }

        public static bool Encrypt { get; set; }

        static void Main(string[] args)
        {
            if (ArgsManager.TryPopulateArguments(args))
                ManageB0Cipher();
        }

        private static string[] TestSetArgs()
        {
            return new string[]
            {
                "-es",
                "The quick brown fox jumped over the lazy dog.",
                "-p",
                "ThisisaBADPassword"
            };
        }

        private static void ManageB0Cipher()
        {
            switch (ArgsManager.Request)
            {
                case RequestType.EncryptFile:
                    Encrypt = true;
                    B0Cipher ef = new B0Cipher(Passphrase);
                    if (ArgsManager.SourceFile != null && ArgsManager.SourceFile != string.Empty)
                        ef.EncryptFile(ArgsManager.SourceFile, ArgsManager.DestinationFile);
                    break;
                case RequestType.DecryptFile:
                    Encrypt = false;
                    B0Cipher df = new B0Cipher(Passphrase);
                    if (ArgsManager.SourceFile != null && ArgsManager.SourceFile != string.Empty)
                        df.DecryptFile(ArgsManager.SourceFile, ArgsManager.DestinationFile);
                    break;
                case RequestType.EncryptString:
                    Encrypt = true;
                    B0Cipher es = new B0Cipher(Passphrase);
                    if (ArgsManager.SourceString != null && ArgsManager.SourceString != string.Empty)
                        Console.WriteLine("Cipher Text [{0}]", es.EncryptString(ArgsManager.SourceString));
                    break;
                case RequestType.DecryptString:
                    Encrypt = false;
                    B0Cipher ds = new B0Cipher(Passphrase);
                    if (ArgsManager.SourceString != null && ArgsManager.SourceString != string.Empty)
                        Console.WriteLine("Original Text [{0}]", ds.DecryptString(ArgsManager.SourceString));
                    break;
                default:
                    break;
            }
        }
    }
}
