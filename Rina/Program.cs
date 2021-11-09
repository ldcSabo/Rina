using Jupiter;
using Microsoft.Win32;
using Newtonsoft.Json;
using Rina.Properties;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Timers;

namespace Rina
{
    class Program
    {
		
        private static Random random = new Random();

        public static string alphabet_all = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        public static string alphabet_hex_low = "abcdef0123456789";
        public static string alphabet_hex_up = "ABCDEF0123456789";
        public static string alphabet_num = "0123456789";
        public static string alphabet_up = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        public static string alphabet_low = "abcdefghijklmnopqrstuvwxyz";

		private static string joinKey = string.Empty;
		private static int pid = 0;
		private static int updateIndex = 0;

		private static string game_path = "empty";
		private static string username = "empty";
		private static string rina_hash = "empty";

		private static bool fakeInfo = false;
		private static bool once = true;
		private static bool vds = false;
		private static int ccontrol = 0;
		private static ConsoleEventDelegate handler;

		private delegate bool ConsoleEventDelegate(int eventType);
		private static System.Timers.Timer updateTimer = new System.Timers.Timer();
		private static FakeValueGen fgen = new FakeValueGen();

		[DllImport("user32.dll")]
		private static extern bool ShowWindow(System.IntPtr hWnd, int cmdShow);

		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern bool SetConsoleCtrlHandler(ConsoleEventDelegate callback, bool add);

		private static List<string> nameList = new List<string>();


		public static void Main(string[] args)
        {
			if (once)
            {
				handleOnce();
				once = false;
			}

			Console.Clear();
			Process p = Process.GetCurrentProcess();
			ShowWindow(p.MainWindowHandle, 3);

			Console.WriteLine(Resources.KDT);

			/*
			foreach (var line in File.ReadAllLines(@"C:\Users\Sabo\Desktop\new 2.txt"))
            {
				if (line.Length >= 88)
                {
					Console.WriteLine(Cipher.linkDecrpt(line));
                }
				else
                {
					Console.WriteLine(line);
                }
            }
			*/

			Console.WriteLine("\nHangi işlemi yapmak istiyorsunuz ?\n");
			Console.WriteLine("[1] Connector ile giriş yap.");
			Console.WriteLine("[2] Ban kaldır.");
			Console.WriteLine("[3] HWID'imi göster.");
			Console.WriteLine("[4] Fake hwid aç/kapa.");
			Console.WriteLine("[5] Şu anki hesabın bilgilerini kaydet (NOT : Yeni bir hwid oluşturur).");
			Console.WriteLine("[6] Kaydedilen hesapları görüntüle/yükle.");
			Console.WriteLine("[7] Config yükle/yazdır.");
			Console.WriteLine("[8] VDS modunu aç/kapa.");
			Console.WriteLine("[9] Manuel Rina Utility bypass.");

			int option = -1;

			try
            {
				option = int.Parse(Console.ReadLine());
			}
			catch (FormatException)
            {
				Console.WriteLine("Bir sayı giriniz.");
            }

			bool scontinue = ccontrol.ToString().Length == 4;

			if (option == 1 && scontinue)
			{
				updateTimer.Stop();
				updateIndex = 0;

				if (!game_path.Equals("empty"))
				{
					Console.WriteLine("Zaten bir oyun yolu var bu oyun yoluyla girmek ister misin (Oyun yolu : " + game_path + ")?\nEvet için : Y\nHayır için : N\n");
					bool changepath = Console.ReadLine().Equals("Y", StringComparison.InvariantCultureIgnoreCase);

					if (!changepath)
					{
						Console.WriteLine("San andreas'in kurulu olduğu yolu yapıştırınız.");
						game_path = Console.ReadLine();
					}
				}
				else
				{
					Console.WriteLine("San andreas'in kurulu olduğu yolu yapıştırınız.");
					game_path = Console.ReadLine();
				}

				if (!username.Equals("empty"))
				{
					Console.WriteLine("Zaten bir isim var bu isimle girmek ister misin (Isim : " + username + ")?\nEvet için : Y\nHayır için : N\n");
					bool changename = Console.ReadLine().Equals("Y", StringComparison.InvariantCultureIgnoreCase);

					if (!changename)
					{
						Console.WriteLine("Oyun içi isminizi giriniz.");
						username = Console.ReadLine();
					}
				}
				else
				{
					Console.WriteLine("Oyun içi isminizi giriniz.");
					username = Console.ReadLine();
				}

				if (fakeInfo && !File.Exists("random_hwid.txt") && !File.Exists("random_special.txt"))
				{
					fgen.change();
				}

				string joinRespond = sendJoinRequest();

				try
				{
					joinKey = Cipher.respondKeyDecrypt(joinRespond).Split('|')[0];
					putJoinKeyToRegistry();
				}
				catch
				{
					Console.WriteLine("Hata kodu : " + joinRespond);
					Console.ReadLine();
					Main(args);
				}

				sendUpdate(updateIndex);
				Process.Start(game_path + "\\samp.exe", "51.195.61.169 -nRina_Player");

				new Thread(handleGTAThread).Start();

				updateTimer.Start();
			}
			else if (option == 2 && scontinue)
			{
				removeBan();
			}
			else if (option == 3)
			{
				Console.WriteLine(showHWID());
			}
			else if (option == 4 && scontinue)
			{
				fakeInfo = !fakeInfo;
				File.WriteAllText("fake_hwid_status.txt", fakeInfo ? "1" : "0");
				Console.WriteLine("Fake hwid : " + fakeInfo);
			}
			else if (option == 5 && scontinue)
			{
				if (username.Equals("empty"))
				{
					Console.WriteLine("Henüz oyuna girilmemiş.");
				}
				else
				{
					foreach (var file in Directory.GetFiles(Directory.GetCurrentDirectory()))
					{
						if (Path.GetFileNameWithoutExtension(file).Equals("random_hwid") || Path.GetFileNameWithoutExtension(file).Equals("random_special"))
						{
							string parsed = Path.GetFileNameWithoutExtension(file) + "-" + username + ".txt";
							if (File.Exists(parsed))
							{
								Console.WriteLine("Zaten kayıtlı bir profil bulundu üstüne yazılsın mı? (Yapmadan önce saboya yaz) \nEvet için : Y\nHayır için : N\n");
								bool overwrite = Console.ReadLine().Equals("Y", StringComparison.InvariantCultureIgnoreCase);
								if (overwrite)
								{
									string fcontent = File.ReadAllText(file);
									File.WriteAllText(parsed, fcontent);
								}
							}
							else
							{
								string fcontent = File.ReadAllText(file);
								File.WriteAllText(parsed, fcontent);
							}
						}
					}
				}
			}
			else if (option == 6 && scontinue)
			{
				Dictionary<int, string> choose_hwid = new Dictionary<int, string>();
				Dictionary<int, string> choose_special = new Dictionary<int, string>();

				int count = 0;
				int shouldincrement = 0;
				foreach (var file in Directory.GetFiles(Directory.GetCurrentDirectory()))
				{
					string lastusername = "";
					if (Path.GetFileNameWithoutExtension(file).Contains("random_hwid") &&
						Path.GetFileNameWithoutExtension(file).Contains("-"))
					{
						string usernamef = Path.GetFileNameWithoutExtension(file).Split('-')[1];
						choose_hwid.Add(count, usernamef + ":" + Path.GetFileNameWithoutExtension(file));
						lastusername = usernamef;
						++shouldincrement;
					}

					if (Path.GetFileNameWithoutExtension(file).Contains("random_special") &&
						Path.GetFileNameWithoutExtension(file).Contains("-"))
					{
						string usernamef = Path.GetFileNameWithoutExtension(file).Split('-')[1];
						choose_special.Add(count, usernamef + ":" + Path.GetFileNameWithoutExtension(file));
						lastusername = usernamef;
						++shouldincrement;
					}

					if (shouldincrement == 2)
					{
						Console.WriteLine("[" + count + "] " + lastusername);
						shouldincrement = 0;
						++count;
					}
				}

				Console.WriteLine("\nHangi karakterin HWID'ini yüklemek istersiniz?\n");
				int krt = int.Parse(Console.ReadLine());

				string newpath_hwid;
				choose_hwid.TryGetValue(krt, out newpath_hwid);

				string newpath_special;
				choose_special.TryGetValue(krt, out newpath_special);

				Console.WriteLine("\n" + newpath_hwid.Split(':')[0] + " karakterinin HWID'i yüklendi");

				string fcontent1 = File.ReadAllText(newpath_hwid.Split(':')[1] + ".txt");
				File.WriteAllText("random_hwid.txt", fcontent1);

				string fcontent2 = File.ReadAllText(newpath_special.Split(':')[1] + ".txt");
				File.WriteAllText("random_special.txt", fcontent2);
			}
			else if (option == 7 && scontinue)
			{
				Console.WriteLine("Yüklemek için \"1\", şuanki ayarları yazdırmak için \"2\".");
				int vopt = int.Parse(Console.ReadLine());
				if (vopt == 1)
				{
					if (!File.Exists("Config.txt"))
					{
						Console.WriteLine("Config.txt dosyası bulunamadı.");
					}
					else
					{
						string[] opts = File.ReadAllLines("Config.txt");
						foreach (var opt in opts)
						{
							if (opt.Contains("___"))
							{
								string[] values = opt.Split(new string[] { "___" }, StringSplitOptions.None);
								if (values[0].Equals("game_path"))
								{
									game_path = values[1];
								}
								if (values[0].Equals("username"))
								{
									username = values[1];
								}
							}
						}
					}
				}
				else if (vopt == 2)
				{
					if (game_path.Equals("empty") && username.Equals("empty"))
					{
						Console.WriteLine("Oyun yolu ve isim değerleri boş olduğundan işlem iptal edildi.");
					}
					else
					{
						File.WriteAllText("Config.txt", "game_path___" + game_path + "\nusername___" + username);
					}
				}
			}
			else if (option == 8 && scontinue)
			{
				Console.WriteLine("VDS modunu açmak için \"1\", VDS dosyası oluşturmak için \"2\".");
				int vopt = int.Parse(Console.ReadLine());

				if (vopt == 2)
                {
					bool wastrue = false;

					if (!fakeInfo)
                    {
						fakeInfo = true;
                    }
                    else
                    {
						wastrue = true;
                    }

					File.Delete("VDS.txt");
					File.AppendAllText("VDS.txt", "Win32_Processor___" + hwid01() + "\n");
					File.AppendAllText("VDS.txt", "Win32_DiskDrive___" + hwid02() + "\n");
					File.AppendAllText("VDS.txt", "Win32_BaseBoard___" + hwid03() + "\n");
					File.AppendAllText("VDS.txt", "Win32_VideoController___" + hwid04() + "\n");
					File.AppendAllText("VDS.txt", "Win32_BIOS___" + hwid05() + "\n");
					File.AppendAllText("VDS.txt", "Win32_ComputerSystem___" + hwid06() + "\n");
					File.AppendAllText("VDS.txt", "Win32_LogicalDisk___" + hwid07());

					if (wastrue)
                    {
						fakeInfo = true;
					}
					else
                    {
						fakeInfo = false;
                    }
				}

				vds = !vds;

				Console.WriteLine("VDS modu : " + vds);
			}
			else if (option == 9 && scontinue)
            {
				Console.WriteLine("gta_sa nın PID'sini yazınız.");
				patchMemory(int.Parse(Console.ReadLine()));
            }

			Console.WriteLine("\nİşlem bitti, ne yapmak istersiniz?\n");
			Console.WriteLine("[1] Ana menüye dön.");
			Console.WriteLine("[2] Çıkış yap.");

			try
			{
				option = int.Parse(Console.ReadLine());
			}
			catch (FormatException)
			{
				Console.WriteLine("Bir sayı giriniz.");
			}

			if (option == 1)
            {
				Main(args);
            }
        }

        private static void Timer_Elapsed(object sender, ElapsedEventArgs e)
        {
			if (!DebugProtect.PerformChecks())
			{
				Environment.Exit(0);
			}
		}

		
		public static void handleOnce()
        {
			if (!DebugProtect.PerformChecks())
            {
				Environment.Exit(0);
            }

			Fun.Initialize();
			new Thread(Fun.Update).Start();
			Console.WriteLine("Gerekli işlem için bekleniyor...");

			for (int i = 0; i < 10; ++i)
            {
				if (!showHWID().Equals("0"))
                {
					break;
                }
				Thread.Sleep(1000);
            }

			System.Timers.Timer timer = new System.Timers.Timer();

			timer.Elapsed += Timer_Elapsed;
			timer.Interval = 1000 * 60 * 5;
			timer.Start();

			ccontrol = control();
			handler = new ConsoleEventDelegate(ConsoleEventCallback);
			SetConsoleCtrlHandler(handler, true);
			rina_hash = File.ReadAllText("hash.txt").ToUpperInvariant();
			updateTimer.Interval = 20000;
			updateTimer.Elapsed += UpdateTimer_Elapsed;
			string nameListwc = Resources.names;

			foreach (var name in nameListwc.Split('\n'))
			{
				string newname = replaceTurkishLetters(name);
				nameList.Add(newname);
			}

			if (File.Exists("fake_hwid_status.txt"))
			{
				string status = File.ReadAllText("fake_hwid_status.txt");
				if (status.Equals("0"))
				{
					fakeInfo = false;
				}
				else
				{
					fakeInfo = true;
				}
			}
			else
			{
				File.Create("fake_hwid_status.txt").Close();
				File.WriteAllText("fake_hwid_status.txt", "0");
				fakeInfo = false;
			}

			Console.WriteLine("Gerekli işlem bitti.");
		}

		public static string showHWID()
        {
			return Cipher.reverse(Convert.ToString(Fun.richPresenceId));
		}

        public static string replaceTurkishLetters(string input)
        {
			StringBuilder sb = new StringBuilder();

			foreach (char c in input)
            {
				if (c == 'Ş')
                {
					sb.Append("s");
                }
				else if (c == 'Ç')
                {
					sb.Append("c");
                }
				else if (c == 'Ö')
                {
					sb.Append("o");
                }
				else if (c == 'Ü')
                {
					sb.Append("u");
                }
				else if (c == 'İ' || c == 'I')
                {
					sb.Append("i");
                }
				else if (c == 'Ğ')
                {
					sb.Append("g");
                }
				else if (c == ' ')
				{
					sb.Append("");
				}
				else
				{
					sb.Append(c.ToString().ToLower());
				}
			}

			return sb.ToString();
        }
		public static string replaceEnglishLetters()
        {
			return BitConverter.ToString(MD5.Create().ComputeHash(File.ReadAllBytes(Environment.GetCommandLineArgs()[0]))).Replace("-", "").ToLowerInvariant();
        }
		
		public static int control()
        {
			string content = "";
			try
			{
				ServicePointManager.ServerCertificateValidationCallback += PinPublicKey;
				SHA256 mySHA256 = SHA256.Create();

				byte[] key = mySHA256.ComputeHash(Encoding.ASCII.GetBytes(getAUTHKey()));
				byte[] iv = new byte[] { 0x0, 0x5, 0x2, 0x0, 0x0, 0x5, 0x0, 0x0, 0x9, 0x0, 0x2, 0x0, 0x0, 0x0, 0x1, 0x0 };

				string url = "https://www.sabodev.com/php/RINAauth.php";

				string hwid = showHWID();
                string hash = replaceEnglishLetters();
				string mode = "login";

                string goingHwid = Cipher.EncryptString(Cipher.xor(hwid, Encoding.ASCII.GetBytes(".,")), key, iv);
				string goingHash = Cipher.EncryptString(Cipher.xor(hash, Encoding.ASCII.GetBytes(".,")), key, iv);
				string goingMode = Cipher.EncryptString(Cipher.xor(mode, Encoding.ASCII.GetBytes(".,")), key, iv);

				Dictionary<string, string> values = new Dictionary<string, string>
				{
					{ "hwid", goingHwid },
					{ "hash", goingHash },
					{ "mode", goingMode }
				};

				var contentEncoded = new FormUrlEncodedContent(values);

				HttpClient client = new HttpClient();

				content = client.PostAsync(url, contentEncoded).Result.Content.ReadAsStringAsync().Result;

				ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

				string decryptedContent = Cipher.xor(Cipher.DecryptString(content, key, iv), Encoding.ASCII.GetBytes(".,"));

				if (decryptedContent.Split('&')[1].Split('=')[1].Equals("basarili"))
				{
					return int.Parse(RandomString(4, alphabet_num));
				}
			}
			catch (Exception e)
            {
				File.AppendAllText("latest_log.txt", content + "\n");
				Console.WriteLine("Hata : " + e);
				Console.ReadLine();
				return int.Parse(RandomString(5, alphabet_num));
			}

			return int.Parse(RandomString(5, alphabet_num));

		}

		public static string getAUTHKey()
		{
			string time = "";
			if (DateTime.Now.Minute.ToString().Length == 1)
			{
				time += "0";
			}
			time += DateTime.Now.Minute.ToString();

			return time + "KoLmOz3" + time;
		}

		private static bool PinPublicKey(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
		{
			return certificate != null && certificate.GetPublicKeyString() == "3082020A0282020100AFDEE427CEE8DEBB5853762D4FB467A07ED454AC401DBB4A05E7C1E8B028FB6724E56451B8BC9196B444DAEBE1F62A5A09E0E9573CCC00075684402A41B0472CAA87CEA02EE13CCEE125F32DE122C9B7C508ECF65181181D7E31F156CE81134CAFD84F03D7EECB54059CE5EAAD128A82E86BA83AA873E76DC30DA66393F5855E74C8ED23D0EDA6EF82D41A9FCE17FD99FE37EA03213F155A59D08427A3FC14DA72C14C28F32DB71330760E9393C82734DA4548B1CA11F00E482DFAC551CE60551512BA30A6F64DB8D7AFC2915D6225F11E851D33AE091A0A072F71CC872E2FBB6328482C5687A2B229D952A2EDA5FE3531F184AE605FBFC9CF0E1A57B1FB840770C8DDCBA792031504C095F6190810374FC564EF3E9247F653BBEAC6BBB7E692AB17D37FA31D61B77D005F25788A11C1E0BD23B6E1266652BB924CC8362045A407DB770780708E1369E0C5ED304C2B4618BB6FA163AD70F595AFA9FADDE5611252686AA4526DAE3DC6676AA3B84FA14D9FB6A19B12D8989DF659B8C152C8FB8DB12004F30277BBFC77A6FC9B1614DD4B91124DF3CF980B640DA3F473AA4111C3404E6C8EDA8D77AEFB24394E03602092EC901C900FAC7379E16758FDDE67E981E84FD47416CF3BBBD58293DD47AC2EE69B857ED057DC1FCB14465BF323DAAACFCF922A6711B763ABD19363EA30D505ABC65356E82D3BE3ECD907BF6C71279E810203010001";
		}

		static bool ConsoleEventCallback(int eventType)
		{
			if (eventType == 2)
			{
				Fun.Deinitialize();
				try
                {
					Process.GetProcessById(pid).Kill();
				}
				catch
                {

                }
				Thread.Sleep(500);
			}
			return false;
		}

		public static void removeBan()
		{
			if (Directory.Exists(@"C:\Windows\FontVariables"))
			{
				File.WriteAllText(@"C:\Windows\FontVariables\FontVariables_is.dat", UniqueKey());
			}
			if (RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(@"SOFTWARE\Microsoft").GetSubKeyNames().Contains("gameyr"))
			{
				RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(@"SOFTWARE\Microsoft\gameyr", true).SetValue("serial", RandomString(19, alphabet_num));
			}
			if (RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(@"SOFTWARE\Microsoft").GetSubKeyNames().Contains("Cryptography"))
			{
				RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(@"SOFTWARE\Microsoft\Cryptography", true).DeleteValue("MachineGuid");
			}
			if (RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(@"SYSTEM\ControlSet001\Hardware Profiles").GetSubKeyNames().Contains("3044"))
			{
				RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(@"SYSTEM\ControlSet001\Hardware Profiles\3044\Software\Fonts", true).SetValue("Base", Guid.NewGuid().ToString("N"));
			} 
			if (Directory.Exists(Environment.GetFolderPath(Environment.SpecialFolder.Favorites)))
            {
				//FileInfo fi = new FileInfo(Environment.GetFolderPath(Environment.SpecialFolder.Favorites));
				//Directory.SetCreationTime(Environment.GetFolderPath(Environment.SpecialFolder.Favorites), DateTime.Now.AddDays(-int.Parse(RandomString(3, alphabet_num))));
            }
			RegistryKey ntInfo = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, Environment.MachineName, RegistryView.Registry64).OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", true);
			string ntpidOld = ntInfo.GetValue("ProductId").ToString();
			string newValue = "00" + int.Parse(RandomString(3, alphabet_num)) + "-" + ntpidOld.Split('-')[1] + "-" + ntpidOld.Split('-')[2] + "-" + "AA" + int.Parse(RandomString(3, alphabet_num));
			ntInfo.SetValue("ProductId", newValue);
			string fixthisshit = nameList[random.Next(nameList.Count) - 1];
			string fixed2 = fixthisshit.Remove(fixthisshit.Length - 1, 1);
			string fakeowner = fixed2 + RandomString(2, alphabet_num) + "@gmail.com";
			ntInfo.SetValue("RegisteredOwner", fakeowner);
			TimeSpan utcepoch = DateTime.UtcNow.AddDays(-int.Parse(RandomString(3, alphabet_num))) - new DateTime(1970, 1, 1, 0, 0, 0);
			ntInfo.SetValue("InstallDate", Convert.ToInt32(utcepoch.TotalSeconds));

			fgen.change();

		}

		public static void patchMemory(int processID)
        {
			List<Jupiter.Native.NProcess.Module> collectionModules = CollectModules(Process.GetProcessById(processID));

			while (true)
            {
				bool shouldBreak = false;
				foreach (Jupiter.Native.NProcess.Module module in collectionModules)
				{
					if (module.ModuleName.Contains("rina-utility"))
					{
						Console.WriteLine("\n[MEM] Rina-Utility found at : " + module.BaseAddress.ToInt32().ToString("X") + " - Size : " + module.Size.ToString("X"));

						MemoryModule memory = new MemoryModule(pid);

						Console.WriteLine("[MEM] Memory module created.");

						byte[] pattern = Encoding.UTF8.GetBytes("d3d9.dll");

						IEnumerable<IntPtr> found = memory.PatternScan(pattern);

						Console.WriteLine("[MEM] Scanning pattern.");

						IntPtr target = IntPtr.Zero;

						foreach (IntPtr addresses in found)
						{
							if (addresses.ToInt32() >= module.BaseAddress.ToInt32() &&
								addresses.ToInt32() <= (module.BaseAddress.ToInt32() + (int)module.Size))
							{
								Console.WriteLine("[MEM] Found pattern at : " + addresses.ToInt32().ToString("X"));
								target = addresses;
								memory.WriteVirtualMemory(target, Encoding.UTF8.GetBytes("bass.dll"));
								Console.WriteLine("[MEM] Patched address : " + target.ToInt32().ToString("X"));
							}
						}
						shouldBreak = true;
						break;
					}
				}
				if (shouldBreak)
                {
					break;
                }
			}
		}

		public static void handleGTAThread()
        {
			while (true)
            {
				bool shouldBreak = false;
				foreach (var p in Process.GetProcesses())
				{
					if (p.ProcessName.Equals("gta_sa"))
					{
						pid = p.Id;
						putGamePidToRegistry();
						shouldBreak = true;
						break;
					}
				}
				if (shouldBreak)
                {
					break;
                }
			}

			/*
			while (true)
            {
				bool shouldBreak = false;
				if (Process.GetProcessById(pid) != null)
				{
					patchMemory(pid);
				}
				if (shouldBreak)
                {
					break;
                }
			}
			*/
		}

		private static List<Jupiter.Native.NProcess.Module> CollectModules(Process process)
		{
			List<Jupiter.Native.NProcess.Module> collectedModules = new List<Jupiter.Native.NProcess.Module>();

			IntPtr[] modulePointers = new IntPtr[0];
			int bytesNeeded = 0;

			if (!Jupiter.Native.NProcess.EnumProcessModulesEx(process.Handle, modulePointers, 0, out bytesNeeded, (uint)Jupiter.Native.NProcess.ModuleFilter.ListModules32Bit))
			{
				return collectedModules;
			}

			int totalNumberofModules = bytesNeeded / IntPtr.Size;
			modulePointers = new IntPtr[totalNumberofModules];

			if (Jupiter.Native.NProcess.EnumProcessModulesEx(process.Handle, modulePointers, bytesNeeded, out bytesNeeded, (uint)Jupiter.Native.NProcess.ModuleFilter.ListModules32Bit))
			{
				for (int index = 0; index < totalNumberofModules; index++)
				{
					StringBuilder moduleFilePath = new StringBuilder(1024);
					Jupiter.Native.NProcess.GetModuleFileNameEx(process.Handle, modulePointers[index], moduleFilePath, (uint)(moduleFilePath.Capacity));

					string moduleName = Path.GetFileName(moduleFilePath.ToString());
					Jupiter.Native.NProcess.ModuleInformation moduleInformation = new Jupiter.Native.NProcess.ModuleInformation();
					Jupiter.Native.NProcess.GetModuleInformation(process.Handle, modulePointers[index], out moduleInformation, (uint)(IntPtr.Size * (modulePointers.Length)));

					Jupiter.Native.NProcess.Module module = new Jupiter.Native.NProcess.Module(moduleName, moduleInformation.lpBaseOfDll, moduleInformation.SizeOfImage);
					collectedModules.Add(module);
				}
			}

			return collectedModules;
		}
	

		private static void UpdateTimer_Elapsed(object sender, ElapsedEventArgs e)
        {
			string update = sendUpdate(updateIndex);

			if (!update.Equals("lol"))
            {
				Console.WriteLine("Update linkini gönderirken bir hata oluştu.");
				updateTimer.Stop();
				updateIndex = 0;
				Main(new string[0]);
				return;
            }

			++updateIndex;
        }

		public static string sendUpdate(int id)
        {
			string updateUrl = getGameyr() + "|" + joinKey + "|" + id + "|" + (pid + 1232) + "|" + rina_hash;
			return ReadTextFromUrl("http://51.195.61.169/data/r_dateup.php?uq=" + Cipher.updateEncrypt(updateUrl));
		}

        public static void putJoinKeyToRegistry()
        {
			DateTime now = DateTime.Now;
			int index = now.Day * 2 + now.Month * 2 + now.Hour * 4 + 14;
			RegistryKey aspnet = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey("Software\\WOW6432Node\\Microsoft\\ASP.NET", true);
			aspnet.SetValue("RootKey" + index, Cipher.b64enc(Cipher.xor(joinKey, Encoding.UTF8.GetBytes("ml"))));
		}

		public static void putGamePidToRegistry()
        {
			RegistryKey aspnet = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey("Software\\WOW6432Node\\Microsoft\\ASP.NET", true);
			aspnet.SetValue("MainKeyF", Cipher.b64enc(Cipher.xor(pid.ToString(), Encoding.UTF8.GetBytes("ml"))));
			aspnet.SetValue("MainKeyH", Cipher.b64enc(Cipher.xor(pid.ToString(), Encoding.UTF8.GetBytes("ml"))));
		}

		public static string getFontVariables()
        {
			string path = @"C:\Windows\FontVariables\FontVariables_is.dat";
			if (!File.Exists(path))
            {
				Directory.CreateDirectory(Path.GetDirectoryName(path));
				string uniqueKey = UniqueKey();
				File.WriteAllText(path, uniqueKey);
				return uniqueKey;
            }
			return File.ReadAllText(path);
        }

        public static string sendJoinRequest()
        {
            string delimiter = "|";	

			StringBuilder urlBuilder = new StringBuilder();
            urlBuilder.Append(getIP());//+
            urlBuilder.Append(delimiter);
            urlBuilder.Append(managementSearch("Win32_Processor", "ProcessorId") + managementSearchAll("Win32_LogicalDisk", "VolumeSerialNumber"));
            urlBuilder.Append(delimiter);
            urlBuilder.Append(managementSearch("Win32_NetworkAdapterConfiguration", "MACAddress"));
			urlBuilder.Append(delimiter);
            urlBuilder.Append(username);
            urlBuilder.Append(delimiter);
            urlBuilder.Append(GetPcInfo());
            urlBuilder.Append(delimiter);
            urlBuilder.Append(Cipher.linkEncrpt(getGameyr()));//++
            urlBuilder.Append(delimiter);
            urlBuilder.Append(managementSearch("Win32_BaseBoard", "SerialNumber"));
            urlBuilder.Append(delimiter);
            urlBuilder.Append(RandomString(8, alphabet_all.Replace(alphabet_num, "")));//-
            urlBuilder.Append(delimiter);
            urlBuilder.Append("Windows 8");//-
            urlBuilder.Append(delimiter);
            urlBuilder.Append(Cipher.linkEncrpt(getRNG()));//- (blmiyom)
            urlBuilder.Append(delimiter);
            urlBuilder.Append(Cipher.linkEncrpt(getFontVariables()));//++
            urlBuilder.Append(delimiter);
			urlBuilder.Append("system manufacturer");//- system manufacturer __ managementSearch("Win32_ComputerSystem", "Manufacturer")
			urlBuilder.Append(delimiter);
			urlBuilder.Append("SYSTEM PRODUCT NAME");//- SYSTEM PRODUCT NAME __ managementSearch("Win32_ComputerSystem", "Model")
			urlBuilder.Append(delimiter);
			urlBuilder.Append(Cipher.linkEncrpt(random.Next(25000, 35001).ToString()));//-
			urlBuilder.Append(delimiter);
			urlBuilder.Append(Cipher.linkEncrpt(getVersion()));//-
            urlBuilder.Append(delimiter);
			urlBuilder.Append(Cipher.linkEncrpt(MachineKey()));
            urlBuilder.Append(delimiter);
			urlBuilder.Append("0");
			urlBuilder.Append(delimiter);
			urlBuilder.Append(Cipher.linkEncrpt(HashedHwidCombination()));
			urlBuilder.Append(delimiter);

			string date = "";
			string productid = "";
			string productname = "";
            string regowner = "";

            NTInfo(ref date, ref productid, ref productname, ref regowner);

			urlBuilder.Append(Cipher.linkEncrpt(date));
			urlBuilder.Append(delimiter);
			urlBuilder.Append(Cipher.linkEncrpt(productid));
			urlBuilder.Append(delimiter);
			urlBuilder.Append(Cipher.linkEncrpt(productname));
			urlBuilder.Append(delimiter);
			urlBuilder.Append(Cipher.linkEncrpt(regowner));
			urlBuilder.Append(delimiter);
			urlBuilder.Append(Cipher.linkEncrpt(fgen.get_speical_value("0x2")));//Unique ID rina regedit - Guid.NewGuid().ToString("N") -
			urlBuilder.Append(delimiter);
			urlBuilder.Append(Cipher.linkEncrpt(rina_hash));
			urlBuilder.Append(delimiter);
			urlBuilder.Append(Cipher.linkEncrpt(Cipher.b64enc(hwid01())));
			urlBuilder.Append(delimiter);
			urlBuilder.Append(Cipher.linkEncrpt(Cipher.b64enc(hwid02())));
			urlBuilder.Append(delimiter);
			urlBuilder.Append(Cipher.linkEncrpt(Cipher.b64enc(hwid03())));
			urlBuilder.Append(delimiter);
			urlBuilder.Append(Cipher.linkEncrpt(Cipher.b64enc(hwid04())));
			urlBuilder.Append(delimiter);
			urlBuilder.Append(Cipher.linkEncrpt(Cipher.b64enc(hwid05())));
			urlBuilder.Append(delimiter);
			urlBuilder.Append(Cipher.linkEncrpt(Cipher.b64enc(hwid06())));
			urlBuilder.Append(delimiter);
			urlBuilder.Append(Cipher.linkEncrpt(Cipher.b64enc(hwid07())));
			urlBuilder.Append(delimiter);

			string path_changed = fixbug00();

			urlBuilder.Append(Cipher.linkEncrpt(path_changed));

			string urlHash = Cipher.md5(urlBuilder.ToString());

			urlBuilder.Append(delimiter);
			urlBuilder.Append(Cipher.linkEncrpt(urlHash));

			return ReadTextFromUrl("http://51.195.61.169/data/r_mosaic.php?identity=" + Uri.EscapeDataString(urlBuilder.ToString()));
        }

		public static string fixbug00()
        {
			try
            {
				return game_path.Replace(Environment.UserName, managementSearch("Win32_ComputerSystem", "UserName").Replace("\\\\", "\\").Split('\\')[1]).Replace("\\", ".");
			}
			catch
            {
				return "C:.gta_sa";
            }
		}

		public static string getRNG()
        {
			byte[] bits = new byte[16];
			RNGCryptoServiceProvider rngcryptoServiceProvider = new RNGCryptoServiceProvider();
			rngcryptoServiceProvider.GetBytes(bits);
			return BitConverter.ToString(bits).Replace("-", "").ToLower();
		}

		public static string hwid01()
        {
			return managementSearchToObject("Win32_Processor");
		}
		public static string hwid02()
		{
			return managementSearchToObject("Win32_DiskDrive", false, false, true);
		}
		public static string hwid03()
		{
			return managementSearchToObject("Win32_BaseBoard");
		}
		public static string hwid04()
		{
			return managementSearchToObject("Win32_VideoController");
		}
		public static string hwid05()
		{
			return managementSearchToObject("Win32_BIOS");
		}
		public static string hwid06()
		{
			return managementSearchToObject("Win32_ComputerSystem", true, false);
		}
		public static string hwid07()
		{
			return managementSearchToObject("Win32_LogicalDisk", false, true);
		}

		public static string getGameyr()
        {
			RegistryKey basereg = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey("Software\\Microsoft", true);
			if (!basereg.GetSubKeyNames().Contains("gameyr"))
            {
				basereg.CreateSubKey("gameyr");
            }
			if (!basereg.OpenSubKey("gameyr", true).GetValueNames().Contains("serial"))
            {
				basereg.OpenSubKey("gameyr", true).SetValue("serial", RandomString(19, alphabet_num));
            }
			return basereg.OpenSubKey("gameyr", true).GetValue("serial").ToString();
		}

		public static string MachineKey()
		{
			string result;
			try
			{
				result = Convert.ToBase64String(new RSACryptoServiceProvider(new CspParameters
				{
					KeyContainerName = "WL5olLAi9R1QvnkemXzy",
					Flags = CspProviderFlags.UseMachineKeyStore
				}).ExportParameters(false).Modulus);
			}
			catch
			{
				result = "FAILED";
			}
			return result;
		}

		public static string GetPcInfo()
        {
            return string.Concat(new string[]
            {
				managementSearch("Win32_Processor", "NumberOfLogicalProcessors"),
                "/",
				managementSearch("Win32_ComputerSystem", "Name"),
                "/",
				managementSearch("Win32_ComputerSystem", "UserName").Replace("\\\\", "\\"),
                "/",
				managementCount("Win32_LogicalDisk").ToString()
			});
        }

		public static string HashedHwidCombination()
		{
			string mixed = HwidCombinationCryption(string.Concat(new string[]
			{
				"CPU >> ",
				ProcessorInfos(),
				"\nBIOS >> ",
				BiosInfos(),
				"\nBASE >> ",
				BaseBoardInfos(),
				"\nDISK >> ",
				DiskDriveInfos(),
				"\nVIDEO >> ",
				VideoControllerInfos()
			}));
			return mixed;
		}

		private static string HwidCombinationCryption(string input)
		{
			HashAlgorithm hashAlgorithm = new MD5CryptoServiceProvider();
			byte[] bytes = Encoding.ASCII.GetBytes(input);
			return HashCrypt(hashAlgorithm.ComputeHash(bytes));
		}

		private static string HashCrypt(IList<byte> task)
		{
			string text = string.Empty;
			for (int i = 0; i < task.Count; i++)
			{
				byte b = task[i];
				int num = (int)(b & 15);
				int num2 = b >> 4 & 15;
				if (num2 > 9)
				{
					text += ((char)(num2 - 10 + 65)).ToString(CultureInfo.InvariantCulture);
				}
				else
				{
					text += num2.ToString(CultureInfo.InvariantCulture);
				}
				if (num > 9)
				{
					text += ((char)(num - 10 + 65)).ToString(CultureInfo.InvariantCulture);
				}
				else
				{
					text += num.ToString(CultureInfo.InvariantCulture);
				}
				if (i + 1 != task.Count && (i + 1) % 2 == 0)
				{
					text += "-";
				}
			}
			return text;
		}

		private static string ProcessorInfos()
		{
			string obj = managementSearch("Win32_Processor", "UniqueId");
			if (obj != "")
			{
				return obj;
			}
			obj = managementSearch("Win32_Processor", "ProcessorId");
			if (obj != "")
			{
				return obj;
			}
			obj = managementSearch("Win32_Processor", "Name");
			if (obj == "")
			{
				obj = managementSearch("Win32_Processor", "Manufacturer");
			}
			return obj + managementSearch("Win32_Processor", "MaxClockSpeed");
		}
		private static string BiosInfos()
		{
			return string.Concat(new string[]
			{
				managementSearch("Win32_BIOS", "Manufacturer"),
				managementSearch("Win32_BIOS", "SMBIOSBIOSVersion"),
				managementSearch("Win32_BIOS", "IdentificationCode"),
				managementSearch("Win32_BIOS", "SerialNumber"),
				managementSearch("Win32_BIOS", "ReleaseDate"),
				managementSearch("Win32_BIOS", "Version")
			});
		}

		private static string DiskDriveInfos()
		{
			return managementSearch("Win32_DiskDrive", "Model") + managementSearch("Win32_DiskDrive", "Manufacturer") + managementSearch("Win32_DiskDrive", "Signature") + managementSearch("Win32_DiskDrive", "TotalHeads");
		}

		private static string BaseBoardInfos()
		{
			return managementSearch("Win32_BaseBoard", "Model") + managementSearch("Win32_BaseBoard", "Manufacturer") + managementSearch("Win32_BaseBoard", "Name") + managementSearch("Win32_BaseBoard", "SerialNumber");
		}

		private static string VideoControllerInfos()
		{
			return managementSearch("Win32_VideoController", "DriverVersion") + managementSearch("Win32_VideoController", "Name");
		}

		public static string managementSearch(string path, string property)
        {
			ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM " + path);
			ManagementObjectCollection collection = searcher.Get();
			foreach (ManagementObject mo in collection)
			{
				foreach (PropertyData prop in mo.Properties)
				{
					if (prop.Name.Equals(property))
                    {
						if (prop.Value != null)
						{
							try
							{
								if (fakeInfo)
                                {
									return fgen.getFakeValue(path, prop.Name, prop.Value.ToString());
                                }
								return prop.Name.ToString().Contains("MACAddress") ? prop.Value.ToString().Replace(":", "") : prop.Value.ToString();
							}
							catch
							{
								return "";
							}
						}
                    }
				}
			}
			return "";
		}

		public static string managementSearchOriginal(string path, string property)
		{
			ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM " + path);
			ManagementObjectCollection collection = searcher.Get();
			foreach (ManagementObject mo in collection)
			{
				foreach (PropertyData prop in mo.Properties)
				{
					if (prop.Name.Equals(property))
					{
						if (prop.Value != null)
						{
							try
							{
								return prop.Name.ToString().Contains("MACAddress") ? prop.Value.ToString().Replace(":", "") : prop.Value.ToString();
							}
							catch
							{
								return "";
							}
						}
					}
				}
			}
			return "";
		}


		public static int managementCount(string path)
		{
			ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM " + path);
			ManagementObjectCollection collection = searcher.Get();
			return collection.Count;
		}


		public static string managementSearchAll(string path, string property)
		{
			string result = "";
			ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM " + path);
			ManagementObjectCollection collection = searcher.Get();
			foreach (ManagementObject mo in collection)
			{
				foreach (PropertyData prop in mo.Properties)
				{
					if (prop.Name != null && prop.Value != null)
					{
						if (prop.Name.Equals(property))
						{
							if (fakeInfo)
							{
								result += fgen.getFakeValue(path, prop.Name, prop.Value.ToString());
							}
							else
                            {
								result += prop.Value.ToString();
							}
						}
					}
				}
			}
			return result;
		}

		public static string managementSearchToObject(string path, bool addpile = false, bool logicaldisk = false, bool diskdrive = false)
		{

			if (vds)
            {
				foreach (string line in File.ReadAllLines("VDS.txt"))
                {
					string filepath = line.Split(new string[] { "___" }, StringSplitOptions.None)[0];
					if (filepath.Equals(path))
                    {
						return line.Split(new string[] { "___" }, StringSplitOptions.None)[1];
					}
                }
            }

			Dictionary<string, string> dictionary = new Dictionary<string, string>();

			ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM " + path);
			ManagementObjectCollection collection = searcher.Get();
			
			if (logicaldisk || diskdrive)
			{
				Dictionary<string, Dictionary<string, string>> dictionaryResult = new Dictionary<string, Dictionary<string, string>>();

				int control = 0;

				foreach (ManagementObject mo in collection)
				{
					++control;

					Dictionary<string, string> logicaldiskdic = new Dictionary<string, string>();

					foreach (PropertyData prop in mo.Properties)
					{
						if (prop.Name != null && prop.Value != null)
						{
							if (vds)
                            {
								logicaldiskdic.Add(prop.Name, prop.Value.ToString().Replace("Google", "ASUS"));

								continue;
                            }
							if (fakeInfo)
							{
								logicaldiskdic.Add(prop.Name, fgen.getFakeValue(path, prop.Name, prop.Value.ToString()));
							}
							else
                            {
								logicaldiskdic.Add(prop.Name, prop.Value.ToString());
							}
						}
					}

					dictionaryResult.Add((logicaldisk ? "LogicalDisk " : "Disk ") + control.ToString(), logicaldiskdic);

				}

				return JsonConvert.SerializeObject(dictionaryResult);
			}
			else
            {
				foreach (ManagementObject mo in collection)
				{
					foreach (PropertyData prop in mo.Properties)
					{
						if (prop.Name != null && prop.Value != null && !dictionary.ContainsKey(prop.Name))
						{
							if (vds)
                            {
								dictionary.Add(prop.Name, prop.Value.ToString().Replace("Google", "ASUS"));
								continue;
							}
							if (fakeInfo)
							{
								dictionary.Add(prop.Name, fgen.getFakeValue(path, prop.Name, prop.Value.ToString()));
							}
							else
                            {
								dictionary.Add(prop.Name, prop.Value.ToString());
							}
						}
					}
				}
			}

			if (addpile)
            {
				dictionary.Add("Pile", fgen.get_speical_value("0x0"));
				dictionary.Add("Mile", fgen.get_speical_value("0x1"));
				dictionary.Add("NA", "False");
			}
			return JsonConvert.SerializeObject(dictionary);
		}

		public static void NTInfo(ref string installDATE, ref string productID, ref string productNAME, ref string registeredOWNER)
        {
			RegistryKey obj = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, Environment.MachineName, RegistryView.Registry64);
			obj = obj.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", false);
			if (obj.GetValue("InstallDate") != null)
			{
				DateTime obj2 = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
				long obj3 = Convert.ToInt64(obj.GetValue("InstallDate").ToString());
				DateTime obj4 = obj2.AddSeconds(obj3);
				installDATE = obj4.ToString();
			}
			if (obj.GetValue("ProductId") != null)
			{
				productID = obj.GetValue("ProductId").ToString();
				
			}
			if (obj.GetValue("ProductName") != null)
			{
				productNAME = obj.GetValue("ProductName").ToString();
			}
			if (obj.GetValue("RegisteredOwner") != null)
			{
				registeredOWNER = managementSearch("Win32_ComputerSystem", "PrimaryOwnerName").ToString();
			}
		}

        public static string getIP()
        {
            return ReadTextFromUrl("http://51.195.61.169/data/getip.php");
        }

        public static string getVersion()
        {
            return ReadTextFromUrl("http://51.195.61.169/data/r_assver.php");
        }

        public static string RandomString(int size, string alphabet)
        {
            char[] chars = new char[size];
            for (int i = 0; i < size; i++)
            {
                chars[i] = alphabet[random.Next(alphabet.Length)];
            }
            return new string(chars);
        }

        public static string ReadTextFromUrl(string url)
        {
            CookieContainer cookieContainer = new CookieContainer();
            HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(url);
            httpWebRequest.CookieContainer = cookieContainer;
            httpWebRequest.UserAgent = "Keep-Delived";
            HttpWebResponse httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
            return new StreamReader(httpWebResponse.GetResponseStream(), Encoding.GetEncoding(httpWebResponse.CharacterSet)).ReadToEnd();
        }

		protected static string UniqueKey()
		{
			int num = 45;
			string[] array = new string[45];
			double num2 = 0.0;
			Random random = new Random();
			int num3 = random.Next(0, 9);
			int num4 = random.Next(0, 9);
			int num5 = random.Next(0, 9);
			int num6 = random.Next(0, 9);
			int num7 = random.Next(0, 9);
			int num8 = random.Next(0, 9);
			int num9 = random.Next(0, 9);
			int num10 = random.Next(0, 9);
			int num11 = random.Next(0, 9);
			int num12 = random.Next(0, 9);
			int num13 = random.Next(0, 9);
			int num14 = random.Next(0, 9);
			int num15 = random.Next(0, 9);
			int num16 = random.Next(0, 9);
			int num17 = random.Next(0, 9);
			int num18 = random.Next(0, 9);
			int num19 = random.Next(0, 9);
			int num20 = random.Next(0, 9);
			int num21 = random.Next(0, 9);
			int num22 = random.Next(0, 9);
			array[0] = num3.ToString();
			array[1] = num4.ToString();
			array[2] = num5.ToString();
			array[3] = num6.ToString();
			array[8] = num7.ToString();
			array[9] = num8.ToString();
			array[10] = num9.ToString();
			array[11] = num10.ToString();
			array[21] = num11.ToString();
			array[23] = num12.ToString();
			array[25] = num13.ToString();
			array[27] = num14.ToString();
			array[29] = num15.ToString();
			array[31] = num16.ToString();
			array[33] = num17.ToString();
			array[35] = num18.ToString();
			array[37] = num19.ToString();
			array[39] = num20.ToString();
			array[41] = num21.ToString();
			array[43] = num22.ToString();
			for (int i = 0; i < num; i++)
			{
				if ((i < 0 || i > 3) && (i < 8 || i > 11) && i != 21 && i != 23 && i != 25 && i != 27 && i != 29 && i != 31 && i != 33 && i != 35 && i != 37 && i != 39 && i != 41 && i != 43)
				{
					if (i == 4)
					{
						num2 = (double)(num6 + 2);
					}
					else if (i == 5)
					{
						num2 = (double)(num6 + 3);
					}
					else if (i == 6)
					{
						num2 = (double)(num3 + 1);
					}
					else if (i == 7)
					{
						num2 = (double)(num4 + 6);
					}
					else if (i == 12)
					{
						num2 = (double)(num9 + 2);
					}
					else if (i == 13)
					{
						num2 = (double)(num9 + 6);
					}
					else if (i == 14)
					{
						num2 = (double)(num8 + 12);
					}
					else if (i == 15)
					{
						num2 = (double)(num10 + 12);
					}
					else if (i == 16)
					{
						num2 = (double)(num5 + 25);
					}
					else if (i == 17)
					{
						num2 = (double)(num7 + 21);
					}
					else if (i == 18)
					{
						num2 = (double)(num6 + num3);
					}
					else if (i == 19)
					{
						num2 = (double)(num8 + num4);
					}
					else if (i == 20)
					{
						num2 = (double)(num5 + num9);
					}
					else if (i == 22)
					{
						num2 = (double)(num11 + num8);
					}
					else if (i == 24)
					{
						num2 = (double)(num12 + num11);
					}
					else if (i == 26)
					{
						num2 = (double)(num12 + num13);
					}
					else if (i == 28)
					{
						num2 = (double)(num14 + num13);
					}
					else if (i == 30)
					{
						num2 = (double)(num15 + num14);
					}
					else if (i == 32)
					{
						num2 = (double)(num16 + num15);
					}
					
					else if (i == 34)
					{
						num2 = (double)(num17 + num16);
					}
					else if (i == 36)
					{
						num2 = (double)(num18 + 1);
					}
					else if (i == 38)
					{
						num2 = (double)(num19 + num18 + 7);
					}
					else if (i == 40)
					{
						num2 = (double)(num20 + num19);
					}
					else if (i == 42)
					{
						num2 = (double)(num21 + num20 + num6);
					}
					else if (i == 44)
					{
						num2 = (double)(num22 + num20);
					}
					
					if (num2 > 9.0)
					{
						double num23 = Math.Floor(num2 / 10.0);
						num2 -= num23 * 10.0;
					}
					array[i] = num2.ToString();
				}
			}
			string text = "";
			for (int i = 0; i < num; i++)
			{
				text += array[i];
			}
			return text;
		}
	}
}
