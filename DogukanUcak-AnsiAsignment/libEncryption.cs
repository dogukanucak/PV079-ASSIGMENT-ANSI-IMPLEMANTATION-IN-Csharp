/*Simple AES Encryption - Decryption Class
Copyright (C) 2012  George Karpouzas
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;


    /// <summary>
    /// prevent the inheritance of this class
    /// </summary>
    public class libAES
    {
        private static readonly libAES _instance = new libAES();

        /// <summary>
        /// prevent instantiation from other classes
        /// </summary>
        private libAES() { }

        /// <summary>
        /// get instance of the class
        /// </summary>
        /// <returns></returns>
        public static libAES Instance
        {
            get
            {
                return _instance;
            }
        }

        /// <summary>
        /// Decrypt string using AES 128
        /// </summary>
        /// <param name="cipheredtext"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public String Decrypt(String cipheredtext, String key)
        {
            byte[] keybytes = Encoding.UTF8.GetBytes(key);
            byte[] cipheredData = Convert.FromBase64String(cipheredtext);

            RijndaelManaged aes = new RijndaelManaged();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;

            //16 ascii characters for IV
            byte[] IVbytes = Encoding.ASCII.GetBytes("myVerySecretIVKe");

            ICryptoTransform decryptor = aes.CreateDecryptor(keybytes, IVbytes);
            System.IO.MemoryStream ms = new System.IO.MemoryStream(cipheredData);
            CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            StreamReader creader = new StreamReader(cs, Encoding.UTF8);

            String Base64 = creader.ReadToEnd();

            ms.Close();
            cs.Close();

            return Encoding.UTF8.GetString(Convert.FromBase64String(Base64));
        }

        /// <summary>
        /// Encrypt string using AES 128
        /// </summary>
        /// <param name="plaintext"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] plaintext, byte[] key)
        {
            RijndaelManaged aes = new RijndaelManaged();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            byte[] IVbytes = Encoding.ASCII.GetBytes("myVerySecretIVKe"); // can be randomly

            ICryptoTransform encryptor = aes.CreateEncryptor(key, IVbytes);
            System.IO.MemoryStream ms = new System.IO.MemoryStream();
            CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);             
            cs.Write(plaintext, 0, plaintext.Length);
            cs.FlushFinalBlock();
            byte[] cipherBytes = ms.ToArray();
            ms.Close();
            cs.Close();

            return cipherBytes;
        }
    }
