using CommandLine;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;

namespace ThreatCheck
{
    class Program
    {
        public class Options
        {
            [Option('e', "engine", Default = "Defender", Required = false, HelpText = "Scanning engine. Options: Defender, AMSI")]
            public string Engine { get; set; }

            [Option('f', "file", Required = false, HelpText = "Analyze a file on disk")]
            public string InFile { get; set; }

            [Option('u', "url", Required = false, HelpText = "Analyze a file from a URL")]
            public string InUrl { get; set; }

            [Option('t', "filetype", Default = "Bin", Required = false, HelpText = "File type to scan. Options: Bin, Script")]
            public string FileType { get; set; }
        }

        public enum ScanningEngine
        {
            Defender,
            Amsi
        }

        static void Main(string[] args)
        {
            var watch = Stopwatch.StartNew();

            Parser.Default.ParseArguments<Options>(args)
                .WithParsed(RunOptions)
                .WithNotParsed(HandleParseError);

            watch.Stop();

#if DEBUG
            CustomConsole.WriteDebug($"Run time: {Math.Round(watch.Elapsed.TotalSeconds, 2)}s");
#endif
        }

        static void RunOptions(Options opts)
        {
            byte[] fileContent = null;
            string scriptContent = null;           
            var engine = (ScanningEngine)Enum.Parse(typeof(ScanningEngine), opts.Engine, true);

            if (!string.IsNullOrEmpty(opts.InUrl))
            {
                try
                {
                   fileContent = DownloadFile(opts.InUrl);
                }
                catch
                {
                    CustomConsole.WriteError("Could not connect to URL");
                    return;
                }
                
            }
            else if (!string.IsNullOrEmpty(opts.InFile))
            {
                if (File.Exists(opts.InFile) && opts.FileType =="Bin")
                {
                    Console.WriteLine("getting bytes");
                    fileContent = File.ReadAllBytes(opts.InFile);
                }
                else if(File.Exists(opts.InFile) && opts.FileType == "Script")
                {
                    Console.WriteLine("getting string");
                    scriptContent = File.ReadAllText(opts.InFile);
                }
                else
                {
                    CustomConsole.WriteError("File not found");
                    return;
                }
            }
            else
            {
                CustomConsole.WriteError("File or URL required");
                return;
            }

            switch (engine)
            {
                case ScanningEngine.Defender:
                    Console.WriteLine("Scanning with Defender");
                    if (fileContent != null)
                    {
                        ScanWithDefender(fileContent);
                    }
                    else
                    {
                        Console.WriteLine("scritps don't work with defender yet");
                    }
                    
                    
                    break;
                case ScanningEngine.Amsi:
                    Console.WriteLine("scanning with AMSI");
                    if (fileContent != null)
                    {
                        ScanWithAmsi(fileContent);
                    }
                    else
                    {
                        ScanWithAmsi(scriptContent);
                    }                    
                    break;
                default:
                    break;
            }
        }

        static void HandleParseError(IEnumerable<Error> errs)
        {
            foreach (Error err in errs)
            {
                Console.Error.WriteLine(err.ToString());
            }
        }
      
        static byte[] DownloadFile(string url)
        {
            using (var client = new WebClient())
            {
                return client.DownloadData(url);
            }
        }

        static void ScanWithDefender(byte[] file)
        {
            var defender = new Defender(file);
            defender.AnalyzeFile();
        }

        static void ScanWithAmsi(byte[] file)
        {
            using (var amsi = new AmsiInstance())
            {
                if (!amsi.RealTimeProtectionEnabled)
                {
                    CustomConsole.WriteError("Ensure real-time protection is enabled");
                    return;
                }
                amsi.AnalyzeBytes(file);
            }
        }
        //There was an issue with the way bytes were converted when using File.ReadAllBytes
        //that causedd the bytes to not properly match signatures compared to when being ran. 
        //The string has be decode from unicode in order to get proper detections 
        static void ScanWithAmsi(string file)
        {
            
            byte[] filebytes = System.Text.Encoding.Unicode.GetBytes(file);
            using (var amsi = new AmsiInstance())
            {
                if (!amsi.RealTimeProtectionEnabled)
                {
                    CustomConsole.WriteError("Ensure real-time protection is enabled");
                    return;
                }
                amsi.AnalyzeBytes(filebytes);
            }
        } 
    }
}