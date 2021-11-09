using DiscordRPC;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Timers;
using System.Windows;

namespace Rina
{
	public class Fun
    {
		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern IntPtr GetConsoleWindow();

		[DllImport("user32")]
		public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int x, int y, int cx, int cy, int flags);

		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern IntPtr CreateFile(
			string lpFileName,
			int dwDesiredAccess,
			int dwShareMode,
			IntPtr lpSecurityAttributes,
			int dwCreationDisposition,
			int dwFlagsAndAttributes,
			IntPtr hTemplateFile);

		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern bool GetCurrentConsoleFont(
			IntPtr hConsoleOutput,
			bool bMaximumWindow,
			[Out][MarshalAs(UnmanagedType.LPStruct)] ConsoleFontInfo lpConsoleCurrentFont);

		[StructLayout(LayoutKind.Sequential)]
		internal class ConsoleFontInfo
		{
			internal int nFont;
			internal Coord dwFontSize;
		}

		[StructLayout(LayoutKind.Explicit)]
		internal struct Coord
		{
			[FieldOffset(0)]
			internal short X;
			[FieldOffset(2)]
			internal short Y;
		}

		private const int GENERIC_READ = unchecked((int)0x80000000);
		private const int GENERIC_WRITE = 0x40000000;
		private const int FILE_SHARE_READ = 1;
		private const int FILE_SHARE_WRITE = 2;
		private const int INVALID_HANDLE_VALUE = -1;
		private const int OPEN_EXISTING = 3;

		static int[] cColors = { 0x000000, 0x000080, 0x008000, 0x008080, 0x800000, 0x800080, 0x808000, 0xC0C0C0, 0x808080, 0x0000FF, 0x00FF00, 0x00FFFF, 0xFF0000, 0xFF00FF, 0xFFFF00, 0xFFFFFF };

		public static void ConsoleWritePixel(Color cValue)
		{
			Color[] cTable = cColors.Select(x => Color.FromArgb(x)).ToArray();
			char[] rList = new char[] { (char)9617, (char)9618, (char)9619, (char)9608 }; // 1/4, 2/4, 3/4, 4/4
			int[] bestHit = new int[] { 0, 0, 4, int.MaxValue }; //ForeColor, BackColor, Symbol, Score

			for (int rChar = rList.Length; rChar > 0; rChar--)
			{
				for (int cFore = 0; cFore < cTable.Length; cFore++)
				{
					for (int cBack = 0; cBack < cTable.Length; cBack++)
					{
						int R = (cTable[cFore].R * rChar + cTable[cBack].R * (rList.Length - rChar)) / rList.Length;
						int G = (cTable[cFore].G * rChar + cTable[cBack].G * (rList.Length - rChar)) / rList.Length;
						int B = (cTable[cFore].B * rChar + cTable[cBack].B * (rList.Length - rChar)) / rList.Length;
						int iScore = (cValue.R - R) * (cValue.R - R) + (cValue.G - G) * (cValue.G - G) + (cValue.B - B) * (cValue.B - B);
						if (!(rChar > 1 && rChar < 4 && iScore > 50000)) // rule out too weird combinations
						{
							if (iScore < bestHit[3])
							{
								bestHit[3] = iScore; //Score
								bestHit[0] = cFore;  //ForeColor
								bestHit[1] = cBack;  //BackColor
								bestHit[2] = rChar;  //Symbol
							}
						}
					}
				}
			}
			Console.ForegroundColor = (ConsoleColor)bestHit[0];
			Console.BackgroundColor = (ConsoleColor)bestHit[1];
			Console.Write(rList[bestHit[2] - 1]);
		}


		public static void ConsoleWriteImage(Bitmap source)
		{
			int sMax = 39;
			decimal percent = Math.Min(decimal.Divide(sMax, source.Width), decimal.Divide(sMax, source.Height));
			Size dSize = new Size((int)(source.Width * percent), (int)(source.Height * percent));
			Bitmap bmpMax = new Bitmap(source, dSize.Width * 2, dSize.Height);
			for (int i = 0; i < dSize.Height; i++)
			{
				for (int j = 0; j < dSize.Width; j++)
				{
					ConsoleWritePixel(bmpMax.GetPixel(j * 2, i));
					ConsoleWritePixel(bmpMax.GetPixel(j * 2 + 1, i));
				}
				System.Console.WriteLine();
			}
			Console.ResetColor();
		}

		private static Size GetConsoleFontSize()
		{
			// getting the console out buffer handle
			IntPtr outHandle = CreateFile("CONOUT$", GENERIC_READ | GENERIC_WRITE,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				IntPtr.Zero,
				OPEN_EXISTING,
				0,
				IntPtr.Zero);
			int errorCode = Marshal.GetLastWin32Error();
			if (outHandle.ToInt32() == INVALID_HANDLE_VALUE)
			{
				throw new IOException("Unable to open CONOUT$", errorCode);
			}

			ConsoleFontInfo cfi = new ConsoleFontInfo();
			if (!GetCurrentConsoleFont(outHandle, false, cfi))
			{
				throw new InvalidOperationException("Unable to get font information.");
			}

			return new Size(cfi.dwFontSize.X, cfi.dwFontSize.Y);
		}

		public static void drawBIRT()
		{
			int height = (int)SystemParameters.PrimaryScreenHeight;
			int width = (int)SystemParameters.PrimaryScreenWidth;
			while (true)
			{
				string path = "birt.png";

				if (!File.Exists(path))
				{
					return;
				}

				using (Graphics g = Graphics.FromHwnd(GetConsoleWindow()))
				{
					using (Image image = Image.FromFile(path))
					{
						Size fontSize = GetConsoleFontSize();

						// translating the character positions to pixels
						Rectangle imageRect = new Rectangle();
						imageRect.X = width - image.Width;
						imageRect.Y = height - image.Height;

						imageRect.Width = image.Width;
						imageRect.Height = image.Height;

						g.DrawImage(image, imageRect);
					}
				}
			}
		}

		public static DiscordRpcClient client;
		private static RichPresence rpc = new RichPresence()
		{
			Details = "Rinada takılıyoring",
			Timestamps = Timestamps.Now,
			Assets = new Assets()
			{
				LargeImageKey = "image_large",
				LargeImageText = "Bas geri aslan.",
				SmallImageKey = "image_small"
			}
		};
		public static bool finished = false;

		public static void Initialize()
		{
			client = new DiscordRpcClient("884054999833907260");

			client.Initialize();

			client.SetPresence(rpc);
		}

		public static ulong richPresenceId = 0;

		public static void Update()
		{
			Timer timer = new Timer(150);
			timer.Elapsed += (sender, args) => { 
				
				if (client.CurrentUser != null && !finished)
                {
					rpc.State = client.CurrentUser.Username + " sıkmaya geldi.";
					richPresenceId = client.CurrentUser.ID;
					client.ClearPresence();
					client.SetPresence(rpc);
					finished = true;
				}

				client.Invoke();
			};
			timer.Start();
		}

		public static void Deinitialize()
		{
			client.Dispose();
		}
	}
}
