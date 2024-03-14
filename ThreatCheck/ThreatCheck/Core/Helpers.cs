using System;
using System.Text;

namespace ThreatCheck
{
    class Helpers
    {
        public static void HexDump(byte[] bytes, int end)
        {

            int fileoffset = end - bytes.Length;
            int offset = 0;
            while (offset < bytes.Length)
            {
                int printOffset = fileoffset + offset;
                if (end == 0)
                {
                    printOffset = 0;
                }
                Console.Write($"{printOffset:X8}   ");

                // Print 16 bytes as hex
                for (int i = 0; i < 16; i++)
                {
                    if (offset + i < bytes.Length)
                    {
                        Console.Write($"{bytes[offset + i]:X2} ");
                    }
                    else
                    {
                        Console.Write("   ");
                    }

                    if (i == 7)
                    {
                        Console.Write(" ");
                    }
                }

                Console.Write("  ");

                // Print 16 bytes as ASCII printable chars
                for (int i = 0; i < 16; i++)
                {
                    if (offset + i < bytes.Length)
                    {
                        char ch = (char)bytes[offset + i];
                        Console.Write(char.IsControl(ch) ? '.' : ch);
                    }
                    else
                    {
                        Console.Write(" ");
                    }
                }

                Console.WriteLine();
                offset += 16;
            }
        }
    }
}
