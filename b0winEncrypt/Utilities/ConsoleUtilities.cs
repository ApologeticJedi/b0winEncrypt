
using System;
using System.Text;

namespace b0winEncrypt.Utilities
{
    public static class ConsoleUtilities
    {

        public static string GetMaskedEntry(string prompt, char maskchar)
        {
            StringBuilder sb = new StringBuilder();
            Console.Write(prompt);
            while (true)
            {
                ConsoleKeyInfo keypress = Console.ReadKey(true);
                if (keypress.Key == ConsoleKey.Backspace && sb.Length > 0)
                {
                    sb.Length--;
                    Console.Write("\b \b");
                }
                else if (keypress.Key == ConsoleKey.Enter)
                    break;
                else
                {
                    sb.Append(keypress.KeyChar);
                    Console.Write(maskchar);
                }
            }
            Console.WriteLine();
            return sb.ToString();
        }

        public static string GetPassPhrase(bool encrypt)
        {
            string returnPassPhrase = String.Empty;
            string prompt = (encrypt)
                ? "Enter a large password/phrase to encrypt with: "
                : "Enter password/phrase to decrypt: ";

            while (true)
            {
                string firstEntry = ConsoleUtilities.GetMaskedEntry(prompt, '*');

                // For encryption we need to validate password and double check before leaving loop.
                if (encrypt)
                {
                    if (firstEntry.Length < 8 || firstEntry.Length > 60)
                    {
                        Console.WriteLine("Passwords or phrases must be between 8 and 60 characters");
                        continue;
                    }
                    else
                    {
                        string secondEntry = ConsoleUtilities.GetMaskedEntry("                     Confirm password/phrase : ", '*');
                        if (!String.Equals(firstEntry, secondEntry))
                        {
                            Console.WriteLine("Passwords/phrases do not match!");
                        }
                        else
                        {
                            returnPassPhrase = firstEntry;
                            break;
                        }
                    }
                }
                else
                {
                    returnPassPhrase = firstEntry;
                    break;
                }
            }
            return returnPassPhrase;
        }
    }
}
