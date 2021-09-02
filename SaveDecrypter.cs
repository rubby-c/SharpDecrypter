using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace save.dat_decoder
{
    public static class SaveDecrypter
    {
        private static unsafe uint Decrypt(byte* data, uint size, int key) //direct translation from ama's c++ one to c#
        {
            uint checksum = 0;
            for (uint i = 0; i < size; i += 1)
            {
                checksum += data[i] + (uint)(key + i);
                data[i] = (byte)(data[i] - (ulong)(2 + key + i));
            }
            return checksum;
        }
        
        private static unsafe uint HashStr(char* encrypted, int length) //direct translation from ama's c++ one to c#
        {
            if (encrypted == null)
                return 0;
            
            uint num = 0x55555555;
            for (int i = 0; i < length; i++)
            {
                num = (num >> 27) + (num << 5) + *encrypted++;
            }
            return num;
        }
        
        [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetVolumeInformation(string Volume, StringBuilder VolumeName, uint VolumeNameSize, out uint SerialNumber, uint SerialNumberLength, uint flags, StringBuilder fs, uint fs_size);
        private static string GetIdentifier()
        {
            if (!GetVolumeInformation("C:\\", null, 0U, out var id, 0U, 0U, null, 0U) && !Program.GetVolumeInformation("D:\\", null, 0U, out id, 0U, 0U, null, 0U) && !Program.GetVolumeInformation("E:\\", null, 0U, out id, 0U, 0U, null, 0U) && !Program.GetVolumeInformation("F:\\", null, 0U, out id, 0U, 0U, null, 0U) && !Program.GetVolumeInformation("G:\\", null, 0U, out id, 0U, 0U, null, 0U))
            {
                return string.Empty;
            }
            return id.ToString();
        }

        public static int FindSequence(byte[] source, byte[] seq) //i pasted this
        {
            var start = -1;
            for (var i = 0; i < source.Length - seq.Length + 1 && start == -1; i++)
            {
                var j = 0;
                for (; j < seq.Length && source[i+j] == seq[j]; j++) {}
                if (j == seq.Length) start = i;
            }
            return start;
        }
        
        private static unsafe void Main(string[] args)
        {
            Console.Write("Place file: ");
            string path = Console.ReadLine();
            if (path != null)
            {
                byte[] unicode = File.ReadAllBytes(path);
                byte[] pattern = { 0x74, 0x61, 0x6E, 0x6B, 0x69, 0x64, 0x5F, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64 };  //this is just tankid_password in bytes, my last approach of all this was some ghetto regex that worked 50% of the times with million string splitting
                
                int startIndex = FindSequence(unicode, pattern) + 19;
                bool found = false;
                int current = startIndex;

                List<byte> pass = new List<byte>();
                while (!found)
                {
                    if (unicode[current] != 0 && unicode[current] != 5)
                    {
                        pass.Add(unicode[current]);
                    }
                    else
                        found = true;
                    
                    current += 1;
                }

                string encrypted = Encoding.Default.GetString(pass.ToArray());
                Console.WriteLine("Encrypted password: " + encrypted);
                
                uint encrypted_len = (uint)encrypted.Length;
                Console.WriteLine("Encrypted password length: " + encrypted_len);
                
                byte[] cutArray = new byte[encrypted_len];
                Array.Copy(pass.ToArray(), cutArray, encrypted_len);
                
                string identifier = GetIdentifier();
                Console.WriteLine("Hard drive identifier: " + identifier);
                
                fixed (char* hwid = identifier)
                {
                    fixed (byte* data = &cutArray[0])
                    {
                        uint key = HashStr(hwid, identifier.Length);
                        Console.WriteLine("Hashed Id: " + key);
                    
                        Decrypt(data, encrypted_len, (int)key);
                    
                        string decrypted = Encoding.Default.GetString(cutArray);
                        Console.WriteLine("Decrypted Pass: " + decrypted);   
                        Console.ReadLine();    
                    }
                }
            }
        }
    }
}
