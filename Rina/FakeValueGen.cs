using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rina
{
    public class FakeValueGen
    {
        private Dictionary<string, string> oldGen = new Dictionary<string, string>();
        private Random rand = new Random();

        public void change()
        {
            if (File.Exists("random_hwid.txt"))
            {
                File.Delete("random_hwid.txt");
            }
            if (File.Exists("random_special.txt"))
            {
                File.Delete("random_special.txt");
            }
            gen();
            special_values();
        }

        private void special_values()
        {
            File.AppendAllText("random_special.txt", "0x0___" + DateTime.Now.AddDays(-int.Parse(Program.RandomString(3, Program.alphabet_num))) + "\n");//Pile
            File.AppendAllText("random_special.txt", "0x1___" + Guid.NewGuid().ToString("N") + "\n");//Mile
            File.AppendAllText("random_special.txt", "0x2___" + Guid.NewGuid().ToString("N"));//UniqueID
        }

        public string get_speical_value(string val)
        {
            if (!File.Exists("random_special.txt"))
            {
                File.Create("random_special.txt").Close();
                special_values();
            }
            string[] fileContent = File.ReadAllLines("random_special.txt");

            foreach (var content in fileContent)
            {
                if (content.StartsWith(val))
                {
                    return content.Split(new string[] { "___" }, StringSplitOptions.None)[1];
                }
            }

            throw new Exception("NEY?");
        }

        public void gen()
        {
            string sysname = "DESKTOP-" + Program.RandomString(6, Program.alphabet_up + Program.alphabet_num);

            string display = Program.managementSearchOriginal("Win32_VideoController", "InstalledDisplayDrivers");

            RegistryKey ntInfo = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, Environment.MachineName, RegistryView.Registry64).OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", true);

            writeFile("Win32_LogicalDisk", "VolumeSerialNumber", Program.RandomString(8, Program.alphabet_hex_up));
            writeFile("Win32_LogicalDisk", "SystemName", sysname);
            writeFile("Win32_ComputerSystem", "DNSHostName", sysname);
            writeFile("Win32_ComputerSystem", "Caption", sysname);
            writeFile("Win32_ComputerSystem", "PrimaryOwnerName", ntInfo.GetValue("RegisteredOwner").ToString());
            writeFile("Win32_ComputerSystem", "Name", sysname);
            writeFile("Win32_ComputerSystem", "UserName", sysname + "\\\\" + "Administrator");
            writeFile("Win32_Processor", "SystemName", sysname);
            writeFile("Win32_VideoController", "SystemName", sysname);
            writeFile("Win32_DiskDrive", "SystemName", sysname);
            writeFile("Win32_BIOS", "SerialNumber", Program.RandomString(10, Program.alphabet_num));
            writeFile("Win32_BaseBoard", "SerialNumber", Program.RandomString(15, Program.alphabet_num));
            writeFile("Win32_DiskDrive", "SerialNumber", Program.RandomString(4, Program.alphabet_hex_up) + "_" + Program.RandomString(4, Program.alphabet_hex_up) + "_" + Program.RandomString(4, Program.alphabet_hex_up) + "_" + Program.RandomString(4, Program.alphabet_hex_up) + "_" + Program.RandomString(4, Program.alphabet_hex_up) + "_" + Program.RandomString(4, Program.alphabet_hex_up) + "_" + Program.RandomString(4, Program.alphabet_hex_up) + "_" + Program.RandomString(4, Program.alphabet_hex_up) + ".");
            writeFile("Win32_Processor", "ProcessorId", Program.managementSearchOriginal("Win32_Processor", "ProcessorId").Substring(0, Program.managementSearchOriginal("Win32_Processor", "ProcessorId").Length - 3) + Program.RandomString(3, Program.alphabet_num));
            writeFile("Win32_BIOS", "ReleaseDate", (int.Parse("2016") + rand.Next(4)) + "" + rand.Next(10, 30) + "" + "0" + rand.Next(9) + "000000.000000+000");
            writeFile("Win32_VideoController", "DriverDate", (int.Parse("2016") + rand.Next(4)) + "" + rand.Next(10, 30) + "" + "0" + rand.Next(9) + "000000.000000+000");
            writeFile("Win32_VideoController", "InstalledDisplayDrivers", displayFake(display));
            writeFile("Win32_NetworkAdapterConfiguration", "MACAddress", Program.RandomString(12, Program.alphabet_hex_up), true);
        }

        private string displayFake(string display)
        {
            try
            {
                string[] paths = display.Split(',');

                StringBuilder result = new StringBuilder();

                foreach (string path in paths)
                {
                    string rest = @"C:\WINDOWS\System32\DriverStore\FileRepository\";
                    if (!path.Contains(rest))
                    {
                        return display;
                    }
                    string fname = Path.GetFileName(path);
                    string tochange = path.Replace(rest, "").Replace(fname, "");
                    tochange = tochange.Remove(tochange.Length - 1, 1);

                    if (tochange.Contains("\\"))
                    {
                        string willcombined = "";
                        string[] changeparts = tochange.Split('\\');

                        foreach (string cpart in changeparts)
                        {
                            if (cpart.Contains("amd64"))
                            {
                                string hwid = cpart.Split(new string[] { "amd64_" }, StringSplitOptions.None)[1];
                                willcombined += cpart.Replace(hwid, Program.RandomString(hwid.Length, Program.alphabet_hex_low)) + "\\";
                            }
                            else
                            {
                                willcombined += cpart.Replace(cpart, Program.RandomString(cpart.Length, Program.alphabet_hex_up)) + "\\";
                            }
                        }
                        result.Append(rest + willcombined + fname + ",");
                    }
                    else
                    {
                        string hwid = tochange.Split(new string[] { "amd64_" }, StringSplitOptions.None)[1];
                        string willcombined = tochange.Replace(hwid, Program.RandomString(hwid.Length, Program.alphabet_hex_low));
                        result.Append(rest + willcombined + "\\" + fname + ",");
                    }
                }

                return result.ToString().Remove(result.Length - 1, 1);
            }
            catch (Exception e)
            {
                Console.WriteLine("#1 display fake value oluşurken hata çıktı : " + e);
                return display;
            }
        }

        public string getFakeValue(string wmic_path, string property_name, string property_value)
        {
            string[] content = File.ReadAllLines("random_hwid.txt");

            foreach (var line in content)
            {
                string[] values = line.Split(new string[] { "___" }, StringSplitOptions.None);

                string wmic_path_f = values[0];
                string property_name_f = values[1];
                string property_value_f = values[2];

                if (wmic_path_f.Equals(wmic_path) && property_name_f.Equals(property_name))
                {
                    if (property_name.ToLowerInvariant().Equals("macaddress"))
                    {
                        return property_value_f.Replace(":", "");
                    }
                    return property_value_f;
                }
            }

            if (property_name.ToLowerInvariant().Equals("macaddress"))
            {
                return property_value.Replace(":", "");
            }
            return property_value;
        }

        private void writeFile(string wmic_path, string property_name, string property_value, bool finalLine = false)
        {
            string original = Program.managementSearchOriginal(wmic_path, property_name);
            if (!isAlreadyDefined(original))
            {
                oldGen.Add(original, property_value);
            }
            else
            {
                property_value = getDefinedValue(original);
            }

            File.AppendAllText("random_hwid.txt", wmic_path + "___" + property_name + "___" + property_value + (finalLine ? "" : "\n"));
        }

        private bool isAlreadyDefined(string original)
        {
            return oldGen.ContainsKey(original);
        }

        private string getDefinedValue(string original)
        {
            return oldGen[original];
        }
    }
}
