using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Rina
{
    public static class Cipher
    {
        private static Random random = new Random();
        public static string[] base64chars = new string[]
        {
            "a",
            "b",
            "c",
            "d",
            "e",
            "f",
            "g",
            "h",
            "i",
            "j",
            "k",
            "l",
            "m",
            "n",
            "o",
            "p",
            "q",
            "r",
            "s",
            "t",
            "u",
            "v",
            "w",
            "x",
            "y",
            "z",
            "A",
            "B",
            "C",
            "D",
            "E",
            "F",
            "G",
            "H",
            "I",
            "J",
            "K",
            "L",
            "M",
            "N",
            "O",
            "P",
            "Q",
            "R",
            "S",
            "T",
            "U",
            "V",
            "W",
            "X",
            "Y",
            "Z",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "0"
        };

        public static string reverse(string ident)
        {
            char[] array = ident.ToCharArray();
            Array.Reverse(array);
            return new string(array);
        }

        public static string md5(string input, bool upper = false)
        {
            MD5 md5 = MD5.Create();
            string hashed = BitConverter.ToString(md5.ComputeHash(Encoding.UTF8.GetBytes(input))).Replace("-", "");
            md5.Clear();
            md5.Dispose();
            return upper ? hashed.ToUpperInvariant() : hashed.ToLowerInvariant();
        }

        public static string respondKeyDecrypt(string input)
        {
            string reversed = reverse(input);
            reversed = reversed.Substring(10);
            int key_index = Convert.ToInt32(reversed.Substring(0, 2));
            reversed = reversed.Substring(2);

            string sezar = sezarDec(reversed, key_index);

            byte[] key_builder = new byte[3];
            key_builder[1] = 78;
            key_builder[0] = 110;
            key_builder[2] = 119;
            SHA256 sha = SHA256.Create();
            byte[] key = sha.ComputeHash(key_builder);
            byte[] iv = new byte[16];
            iv[2] = 119;
            iv[13] = 65;
            iv[12] = 74;
            iv[5] = 52;
            iv[14] = 48;
            iv[3] = 120;
            iv[15] = 106;
            iv[0] = 110;
            iv[7] = 68;
            iv[8] = 67;
            iv[4] = 80;
            iv[6] = 49;
            iv[1] = 78;
            iv[10] = 109;
            iv[11] = 67;
            iv[9] = 114;

            return DecryptString(sezar, key, iv);
        }

        public static string linkDecrpt(string input)
        {
            SHA256 sha = SHA256.Create();

            byte[] xorKey = new byte[]
            {
                85,
                76,
                76,
                117,
                66,
                84,
                51,
                84,
                117,
                71,
                88,
                56,
                110,
                76,
                104,
                108
            };

            byte[] key = new byte[]
            {
                112,
                101,
                112
            };

            byte[] iv = new byte[]
            {
                113,
                71,
                116,
                71,
                71,
                80,
                122,
                56,
                71,
                83,
                83,
                53,
                90,
                109,
                102,
                101
            };


            string dec1 = b64dec(input);
            string dec2 = b64dec(dec1);
            string dec3 = b64dec(dec2);
            string dec4 = xor(decode01(dec3), xorKey);
            string dec5 = sezarIndexDec(dec4);
            string dec6 = DecryptString(dec5, sha.ComputeHash(key), iv);
            return dec6;
        }

        public static string linkEncrpt(string input)
        {
            SHA256 sha = SHA256.Create();

            byte[] xorKey = new byte[]
            {
                85,
                76,
                76,
                117,
                66,
                84,
                51,
                84,
                117,
                71,
                88,
                56,
                110,
                76,
                104,
                108
            };

            byte[] key = new byte[]
            {
                112,
                101,
                112
            };

            byte[] iv = new byte[]
            {
                113,
                71,
                116,
                71,
                71,
                80,
                122,
                56,
                71,
                83,
                83,
                53,
                90,
                109,
                102,
                101
            };

            string enc1 = EncryptString(input, sha.ComputeHash(key), iv);
            string enc2 = sezarIndexEnc(enc1);
            string enc3 = xor(enc2, xorKey);
            string enc4 = encode01(enc3);
            string enc5 = b64enc(enc4);
            string enc6 = b64enc(enc5);
            string enc7 = b64enc(enc6);

            return Uri.EscapeDataString(enc7);
        }

        public static string updateDecrypt(string input)
        {
            SHA256 sha = SHA256.Create();
            byte[] key = new byte[]
            {
                116,
                72,
                106
            };
            byte[] iv = new byte[]
            {
                113,
                71,
                116,
                48,
                55,
                80,
                112,
                56,
                71,
                84,
                84,
                53,
                90,
                109,
                100,
                103
            };
            byte[] xorKey = new byte[]
            {
                85,
                76,
                76,
                117,
                66,
                116,
                51,
                116,
                117,
                71,
                88,
                56,
                110,
                76,
                101,
                74
            };

            string dec1 = b64dec(input);
            string dec2 = b64dec(dec1);
            string dec3 = b64dec(dec2);
            string dec4 = xor(dec3, xorKey);
            string dec5 = reverse(dec4).Substring(10);
            string dec6 = sezarDec(dec5, 32);
            string dec7 = DecryptString(dec6, sha.ComputeHash(key), iv);

            return dec7;
        }

        public static string updateEncrypt(string input)
        {
            SHA256 sha = SHA256.Create();
            byte[] key = new byte[]
            {
                116,
                72,
                106
            };
            byte[] iv = new byte[]
            {
                 113,
                71,
                116,
                48,
                55,
                80,
                112,
                56,
                71,
                84,
                84,
                53,
                90,
                109,
                100,
                103
            };
            byte[] xorKey = new byte[]
            {
                85,
                76,
                76,
                117,
                66,
                116,
                51,
                116,
                117,
                71,
                88,
                56,
                110,
                76,
                101,
                74
            };

            string enc1 = EncryptString(input, sha.ComputeHash(key), iv);
            string enc2 = sezarEnc(enc1, 32);
            string enc3 = reverse(Program.RandomString(10, Program.alphabet_all) + enc2);
            string enc4 = xor(enc3, xorKey);
            string enc5 = b64enc(enc4);
            string enc6 = b64enc(enc5);
            string enc7 = b64enc(enc6);

            return enc7;
        }

        public static string b64enc(string input)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(input));
        }

        public static string b64dec(string input)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(input));
        }

        public static string EncryptString(string plainText, byte[] key, byte[] iv)
        {
            Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            byte[] array = new byte[32];
            Array.Copy(key, 0, array, 0, 32);
            aes.Key = array;
            aes.IV = iv;
            MemoryStream memoryStream = new MemoryStream();
            ICryptoTransform transform = aes.CreateEncryptor();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write);
            byte[] bytes = Encoding.ASCII.GetBytes(plainText);
            cryptoStream.Write(bytes, 0, bytes.Length);
            cryptoStream.FlushFinalBlock();
            byte[] array2 = memoryStream.ToArray();
            memoryStream.Close();
            cryptoStream.Close();
            string converted = Convert.ToBase64String(array2, 0, array2.Length);
            return converted;
        }

        public static string DecryptString(string cipherText, byte[] key, byte[] iv)
        {
            Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            byte[] array = new byte[32];
            Array.Copy(key, 0, array, 0, 32);
            aes.Key = array;
            aes.IV = iv;
            MemoryStream memoryStream = new MemoryStream();
            ICryptoTransform transform = aes.CreateDecryptor();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write);
            string result = string.Empty;
            try
            {
                byte[] array2 = Convert.FromBase64String(cipherText);
                cryptoStream.Write(array2, 0, array2.Length);
                cryptoStream.FlushFinalBlock();
                byte[] array3 = memoryStream.ToArray();
                result = Encoding.ASCII.GetString(array3, 0, array3.Length);
            }
            catch
            {
                Console.WriteLine("Exception caught in : "+ new StackFrame(1).GetMethod().Name);
            }
            finally
            {
                memoryStream.Close();
                cryptoStream.Close();
            }
            return result;
        }


        public static string sezarIndexDec(string input)
        {
            string findrule = reverse(input);
            findrule = findrule.Substring(10);
            int key = Convert.ToInt32(Convert.ToString(findrule.ToCharArray()[0]) + Convert.ToString(findrule.ToCharArray()[1]));
            input = reverse(input);
            input = input.Substring(12);
            return sezarDec(input, key);
        }

        public static string sezarIndexEnc(string input)
        {
            int randomKey = random.Next(10, 62);
            string sezar = sezarEnc(input, randomKey);
            string randomMixed = Program.RandomString(10, Program.alphabet_all) + randomKey + sezar;
            string reversed = reverse(randomMixed);
            return reversed;
        }

        public static int sezarHelper(int start_info, int endpol)
        {
            return (start_info % endpol + endpol) % endpol;
        }

        public static string sezarEnc(string input, int key)
        {
            List<char> obj11 = new List<char>();
            obj11.AddRange(input);
            char[] obj12 = new char[input.Length];
            for (int obj13 = 0; obj13 < obj11.Count; obj13++)
            {
                char obj14 = obj11[obj13];
                string value = obj14.ToString();
                int obj15 = Array.IndexOf<string>(base64chars, value);
                if (obj15 != -1)
                {
                    int obj16 = sezarHelper(obj15 + key, 62);
                    obj12[obj13] = Convert.ToChar(base64chars[obj16]);
                }
                else
                {
                    obj12[obj13] = obj11[obj13];
                }
            }
            return new string(obj12);
        }

        public static string sezarDec(string input, int key)
        {
            List<char> obj11 = new List<char>();
            obj11.AddRange(input);
            char[] obj12 = new char[input.Length];
            for (int obj13 = 0; obj13 < obj11.Count; obj13++)
            {
                char obj14 = obj11[obj13];
                string value = obj14.ToString();
                int obj15 = Array.IndexOf<string>(base64chars, value);
                if (obj15 != -1)
                {
                    int obj16 = sezarHelper(obj15 + (62 - key), 62);
                    obj12[obj13] = Convert.ToChar(base64chars[obj16]);
                }
                else
                {
                    obj12[obj13] = obj11[obj13];
                }
            }
            return new string(obj12);
        }

        public static string encode01(string input)
        {
            char[] stage2 = input.ToCharArray();

            for (int i = 0; i < stage2.Length; ++i)
            {
                bool obj51 = char.IsUpper(stage2[i]);
                int obj52 = char.ToLower(stage2[i]);
                if (obj52 == 'a')//1
                {
                    char obj53 = 'p';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'b')//2
                {
                    char obj53 = 'u';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'c')//3
                {
                    char obj53 = 'o';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'd')//4
                {
                    char obj53 = 'd';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'e')//5
                {
                    char obj53 = 'g';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'f')//6
                {
                    char obj53 = 'l';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'g')//7
                {
                    char obj53 = 'h';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'h')//8
                {
                    char obj53 = 'y';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'i')//9
                {
                    char obj53 = 'i';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'j')//10
                {
                    char obj53 = 'n';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'k')//11
                {
                    char obj53 = 'z';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'l')//12
                {
                    char obj53 = 'x';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'm')//13
                {
                    char obj53 = 'a';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'n')//14
                {
                    char obj53 = 'c';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'o')//15
                {
                    char obj53 = 'f';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'p')//16
                {
                    char obj53 = 'b';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'q')//17
                {
                    char obj53 = 'v';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'r')//18
                {
                    char obj53 = 'm';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 's')//19
                {
                    char obj53 = 't';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 't')//20
                {
                    char obj53 = 'e';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'u')//21
                {
                    char obj53 = 's';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'v')//22
                {
                    char obj53 = 'w';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'w')//23
                {
                    char obj53 = 'j';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'x')//24 -
                {
                    char obj53 = 'k';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'y')//25 -
                {
                    char obj53 = 'q';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'z')//26
                {
                    char obj53 = 'r';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
            }

            return new string(stage2);
        }

        public static string decode01(string input)
        {
            char[] stage2 = input.ToCharArray();

            for (int i = 0; i < stage2.Length; ++i)
            {
                bool obj51 = char.IsUpper(stage2[i]);
                int obj52 = char.ToLower(stage2[i]);
                if (obj52 == 'p')//1
                {
                    char obj53 = 'a';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'u')//2
                {
                    char obj53 = 'b';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'o')//3
                {
                    char obj53 = 'c';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'd')//4
                {
                    char obj53 = 'd';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'g')//5
                {
                    char obj53 = 'e';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'l')//6
                {
                    char obj53 = 'f';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'h')//7
                {
                    char obj53 = 'g';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'y')//8
                {
                    char obj53 = 'h';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'i')//9
                {
                    char obj53 = 'i';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'n')//10
                {
                    char obj53 = 'j';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'z')//11
                {
                    char obj53 = 'k';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'x')//12
                {
                    char obj53 = 'l';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'a')//13
                {
                    char obj53 = 'm';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'c')//14
                {
                    char obj53 = 'n';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'f')//15
                {
                    char obj53 = 'o';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'b')//16
                {
                    char obj53 = 'p';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'v')//17
                {
                    char obj53 = 'q';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'm')//18
                {
                    char obj53 = 'r';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 't')//19
                {
                    char obj53 = 's';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'e')//20
                {
                    char obj53 = 't';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 's')//21
                {
                    char obj53 = 'u';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'w')//22
                {
                    char obj53 = 'v';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'j')//23
                {
                    char obj53 = 'w';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'k')//24
                {
                    char obj53 = 'x';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'q')//25
                {
                    char obj53 = 'y';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
                if (obj52 == 'r')//26
                {
                    char obj53 = 'z';
                    stage2[i] = ((obj51) ? char.ToUpper(obj53) : obj53);
                }
            }

            return new string(stage2);
        }

        public static string xor(string input, byte[] key)
        {
            StringBuilder obj2 = new StringBuilder();
            for (int obj3 = 0; obj3 < input.Length; obj3++)
            {
                char c = (char)(input[obj3] ^ key[obj3 % key.Length]);
                obj2.Append(c);
            }
            return obj2.ToString();
        }
    }
}
