
using System;

namespace b0winEncrypt.Utilities
{
    public static class ArgsManager
    {
        #region constants
        public const string ENCRYPTFILE_FLAG = "-ef";
        public const string DECRYPTFILE_FLAG = "-df";
        public const string ENCRYPTSTRING_FLAG = "-es";
        public const string DECRYPTSTRING_FLAG = "-ds";
        public const string DESTINATION_FLAG = "-o";
        public const string PASSWORD_FLAG = "-p";
        #endregion

        #region fields/properties
        public static RequestType Request { get; set; }
        public static string SourceFile { get; set; }
        public static string DestinationFile { get; set; }
        public static string Passphrase { get; set; }
        public static string SourceString { get; set; }
        #endregion

        #region public methods
        public static bool TryPopulateArguments(string[] args)
        {
            bool returnValue = false;
            if (args == null || args.Length == 0 || args.Length == 1)
                ShowUsage("Try This");
            else if (args.Length % 2 == 1)
                ShowUsage("Invalid number of arguments");
            else
            {
                if (ValidateRequest(args[0]))
                {
                    switch (Request)
                    {
                        case RequestType.EncryptFile:
                        case RequestType.DecryptFile:
                            SourceFile = args[1];
                            if (args.Length == 2)
                            {
                                DestinationFile = SourceFile + ".b0encrypt";
                                returnValue = true;
                            }
                            else 
                            {
                                if (CheckNextArgsSet(args[2], args[3]))
                                    if (args.Length == 4)
                                        returnValue = true;
                                    else if (CheckNextArgsSet(args[4], args[5]))
                                        returnValue = true;
                            }
                            break;
                        case RequestType.EncryptString:
                        case RequestType.DecryptString:
                            SourceString = args[1];
                            if (args.Length == 2)
                                returnValue = true;
                            else if (CheckNextArgsSet(args[2], args[3]))
                                returnValue = true;
                            break;
                        default:
                            returnValue = false;
                            ShowUsage(String.Format("Argument {0} not recognized.", args[0]));
                            break;
                    }
                }
            }
            return returnValue;
        }
        #endregion



        #region private methods
        private static void ShowUsage(string message)
        {
            Console.WriteLine(message);
            Console.WriteLine("\nUSAGE: ");
            Console.WriteLine("   b0winEncrypt -ef \"<filename>\"       - Encrypts a file");
            Console.WriteLine("   b0winEncrypt -df \"<filename>\"       - Decrypts a file");
            Console.WriteLine("   b0winEncrypt -es \"<string>\"         - Encrypts a string");
            Console.WriteLine("   b0winEncrypt -ds \"<string>\"         - Decrypts a string");
            Console.WriteLine("\n Other Options:");
            Console.WriteLine("   -o \"<filename>\"    - Specifies the exact outputfile instead of default.");
            Console.WriteLine("   -p \"<password>\"    - Forces the password. Avoids the password prompt. ");
            Console.WriteLine("   -h / -? / help   - Gives this help screen.");
            Console.WriteLine("\nIt is strongly recommended to surround nonflag parameters in quotes as shown.");
        }

        private static bool ValidateRequest(string request)
        {
            bool returnValue = false;
            switch (request)
            {
                case ENCRYPTFILE_FLAG:
                    Request = RequestType.EncryptFile;
                    returnValue = true;
                    break;
                case DECRYPTFILE_FLAG:
                    Request = RequestType.DecryptFile;
                    returnValue = true;
                    break;
                case ENCRYPTSTRING_FLAG:
                    Request = RequestType.EncryptString;
                    returnValue = true;
                    break;
                case DECRYPTSTRING_FLAG:
                    Request = RequestType.DecryptString;
                    returnValue = true;
                    break;
                default:
                    returnValue = false;
                    ShowUsage(String.Format("Argument {0} not recognized.", request));
                    break;
            }
            return returnValue;
        }

        private static bool CheckNextArgsSet(string flag, string value)
        {
            bool returnValue = false;
            switch (flag)
            {
                case DESTINATION_FLAG:
                    DestinationFile = value;
                    returnValue = true;
                    break;
                case PASSWORD_FLAG:
                    Passphrase = value;
                    returnValue = true;
                    break;
                default:
                    returnValue = false;
                    ShowUsage(String.Format("Argument {0} not recognized.", flag));
                    break;
            }
            return returnValue;
        }
        #endregion
    }
}
