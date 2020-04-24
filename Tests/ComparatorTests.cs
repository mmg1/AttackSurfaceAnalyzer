// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Collectors;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security;
using WindowsFirewallHelper;

namespace AttackSurfaceAnalyzer.Tests
{
    [TestClass]
    public class ComparatorTests
    {
        [TestInitialize]
        public void Setup()
        {
            Logger.Setup(false, true);
            Strings.Setup();
            AsaTelemetry.Setup(test: true);
        }

        [TestMethod]
        public void TestFileCompare()
        {
            var FirstRunId = "TestFileCollector-1";
            var SecondRunId = "TestFileCollector-2";

            var testFolder = AsaHelpers.GetTempFolder();
            Directory.CreateDirectory(testFolder);

            var opts = new CollectCommandOptions()
            {
                RunId = FirstRunId,
                EnableFileSystemCollector = true,
                GatherHashes = true,
                SelectedDirectories = testFolder,
                DownloadCloud = false,
                CertificatesFromFiles = false
            };

            var fsc = new FileSystemCollector(opts);
            fsc.Execute();

            using (var file = File.Open(Path.Combine(testFolder, "AsaLibTesterMZ"), FileMode.OpenOrCreate))
            {
                file.Write(FileSystemUtils.WindowsMagicNumber, 0, 2);
                file.Write(FileSystemUtils.WindowsMagicNumber, 0, 2);

                file.Close();
            }

            using (var file = File.Open(Path.Combine(testFolder, "AsaLibTesterJavaClass"), FileMode.OpenOrCreate))
            {
                file.Write(FileSystemUtils.JavaMagicNumber, 0, 4);
                file.Close();
            }

            opts.RunId = SecondRunId;

            var fsc2 = new FileSystemCollector(opts);
            fsc2.Execute();

            Assert.IsTrue(fsc2.Results.Any(x => x is FileSystemObject FSO && FSO.Path.EndsWith("AsaLibTesterMZ")));
            Assert.IsTrue(fsc2.Results.Any(x => x is FileSystemObject FSO && FSO.Path.EndsWith("AsaLibTesterJavaClass")));

            BaseCompare bc = new BaseCompare();
            bc.Compare(fsc.Results, fsc2.Results, FirstRunId, SecondRunId);

            var results = bc.Results;

            Assert.IsTrue(results.ContainsKey((RESULT_TYPE.FILE, CHANGE_TYPE.CREATED)));
            Assert.IsTrue(results[(RESULT_TYPE.FILE, CHANGE_TYPE.CREATED)].Any(x => x.Identity.Contains("AsaLibTesterMZ") && x.Compare is FileSystemObject FSO && FSO.IsExecutable is bool isExe && isExe));
            Assert.IsTrue(results[(RESULT_TYPE.FILE, CHANGE_TYPE.CREATED)].Any(x => x.Identity.Contains("AsaLibTesterJavaClass") && x.Compare is FileSystemObject FSO && FSO.IsExecutable is bool isExe && isExe));
        }

        /// <summary>
        /// Requires Admin
        /// </summary>
        [TestMethod]
        public void TestEventCompareWindows()
        {
            var FirstRunId = "TestEventCollector-1";
            var SecondRunId = "TestEventCollector-2";

            var elc = new EventLogCollector();
            elc.Execute();

            using EventLog eventLog = new EventLog("Application");
            eventLog.Source = "Attack Surface Analyzer Tests";
            eventLog.WriteEntry("This Log Entry was created for testing the Attack Surface Analyzer library.", EventLogEntryType.Warning, 101, 1);

            var elc2 = new EventLogCollector();
            elc2.Execute();

            Assert.IsTrue(elc2.Results.Any(x => x is EventLogObject ELO && ELO.Source == "Attack Surface Analyzer Tests" && ELO.Timestamp is DateTime DT && DT.AddMinutes(1).CompareTo(DateTime.Now) > 0));

            BaseCompare bc = new BaseCompare();
            bc.Compare(elc.Results, elc2.Results, FirstRunId, SecondRunId);

            var results = bc.Results;

            Assert.IsTrue(results[(RESULT_TYPE.LOG, CHANGE_TYPE.CREATED)].Any(x => x.Compare is EventLogObject ELO && ELO.Level == "Warning" && ELO.Source == "Attack Surface Analyzer Tests"));
        }

        /// <summary>
        /// Does not require Admin.
        /// </summary>
        [TestMethod]
        public void TestPortCompareWindows()
        {
            var FirstRunId = "TestPortCollector-1";
            var SecondRunId = "TestPortCollector-2";

            var opc = new OpenPortCollector();
            opc.Execute();

            TcpListener? server = null;
            try
            {
                // Set the TcpListener on port 13000.
                int port = 13000;
                IPAddress localAddr = IPAddress.Parse("127.0.0.1");

                // TcpListener server = new TcpListener(port);
                server = new TcpListener(localAddr, port);

                // Start listening for client requests.
                server.Start();
            }
            catch (Exception)
            {
                Console.WriteLine("Failed to open port.");
            }

            var opc2 = new OpenPortCollector();
            opc2.Execute();

            server?.Stop();

            Assert.IsTrue(opc2.Results.Any(x => x is OpenPortObject OPO && OPO.Port == 13000));

            BaseCompare bc = new BaseCompare();
            bc.Compare(opc.Results, opc2.Results, FirstRunId, SecondRunId);

            var results = bc.Results;

            Assert.IsTrue(results.ContainsKey((RESULT_TYPE.PORT, CHANGE_TYPE.CREATED)));
            Assert.IsTrue(results[(RESULT_TYPE.PORT, CHANGE_TYPE.CREATED)].Any(x => x.Identity.Contains("13000")));
        }

        /// <summary>
        /// Requires root.
        /// </summary>
        [TestMethod]
        public void TestFirewallCompareOSX()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                var FirstRunId = "TestFirewallCollector-1";
                var SecondRunId = "TestFirewallCollector-2";

                var fwc = new FirewallCollector();
                fwc.Execute();

                _ = ExternalCommandRunner.RunExternalCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--add /bin/bash");

                var fwc2 = new FirewallCollector();
                fwc2.Execute();

                Assert.IsTrue(fwc2.Results.Any(x => x is FirewallObject FWO && FWO.ApplicationName == "/bin/bash"));

                _ = ExternalCommandRunner.RunExternalCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--remove /bin/bash");

                BaseCompare bc = new BaseCompare();
                bc.Compare(fwc.Results, fwc2.Results, FirstRunId, SecondRunId);

                var results = bc.Results;

                Assert.IsTrue(results.ContainsKey((RESULT_TYPE.FIREWALL, CHANGE_TYPE.CREATED)));
                Assert.IsTrue(results[(RESULT_TYPE.FIREWALL, CHANGE_TYPE.CREATED)].Where(x => x.Identity.Contains("/bin/bash")).Count() > 0);
            }
        }

        /// <summary>
        /// Requires root.
        /// </summary>
        [TestMethod]
        public void TestFirewallCompareLinux()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                var FirstRunId = "TestFirewallCollector-1";
                var SecondRunId = "TestFirewallCollector-2";

                var fwc = new FirewallCollector();
                fwc.Execute();

                var result = ExternalCommandRunner.RunExternalCommand("iptables", "-A INPUT -p tcp --dport 19999 -j DROP");

                var fwc2 = new FirewallCollector();
                fwc2.Execute();

                result = ExternalCommandRunner.RunExternalCommand("iptables", "-D INPUT -p tcp --dport 19999 -j DROP");

                BaseCompare bc = new BaseCompare();
                bc.Compare(fwc.Results, fwc2.Results, FirstRunId, SecondRunId);

                var results = bc.Results;

                Assert.IsTrue(results.ContainsKey((RESULT_TYPE.FIREWALL, CHANGE_TYPE.CREATED)));
                Assert.IsTrue(results[(RESULT_TYPE.FIREWALL, CHANGE_TYPE.CREATED)].Where(x => x.Identity.Contains("9999")).Count() > 0);
            }
        }

        /// <summary>
        /// Does not require administrator.
        /// </summary>
        [TestMethod]
        public void TestRegistryCompareWindows()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var FirstRunId = "TestRegistryCollector-1";
                var SecondRunId = "TestRegistryCollector-2";
                var path = "Software";
                var hives = new List<(RegistryHive, string)>() { (RegistryHive.CurrentUser, path) };
                var rc = new RegistryCollector(hives, false);
                rc.Execute();

                // Create a registry key
                var name = Guid.NewGuid().ToString();
                var value = Guid.NewGuid().ToString();
                var value2 = Guid.NewGuid().ToString();

                RegistryKey key;
                key = Registry.CurrentUser.OpenSubKey(path);
                var subKey = key.CreateSubKey(name);
                subKey.SetValue(value, value2);
                subKey.Close();

                var rc2 = new RegistryCollector(hives, false);
                rc2.Execute();

                Assert.IsTrue(rc2.Results.Any(x => x is RegistryObject RO && RO.Key.EndsWith(name)));
                Assert.IsTrue(rc2.Results.Any(x => x is RegistryObject RO && RO.Key.EndsWith(name) && RO.Values != null && RO.Values.ContainsKey(value) && RO.Values[value] == value2));

                // Clean up
                key.DeleteSubKey(name);

                BaseCompare bc = new BaseCompare();

                bc.Compare(rc.Results, rc2.Results, FirstRunId, SecondRunId);

                Assert.IsTrue(bc.Results.ContainsKey((RESULT_TYPE.REGISTRY, CHANGE_TYPE.CREATED)));
                Assert.IsTrue(bc.Results[(RESULT_TYPE.REGISTRY, CHANGE_TYPE.CREATED)].Any(x => x.Compare is RegistryObject RO && RO.Key.EndsWith(name)));
            }
        }

        /// <summary>
        /// Requires Administrator Priviledges.
        /// </summary>
        [TestMethod]
        public void TestServiceCompareWindows()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Assert.IsTrue(AsaHelpers.IsAdmin());
                var FirstRunId = "TestServiceCollector-1";
                var SecondRunId = "TestServiceCollector-2";

                var sc = new ServiceCollector();
                sc.Execute();

                // Create a service - This won't throw an exception, but it won't work if you are not an Admin.
                var serviceName = "AsaDemoService";
                var exeName = "AsaDemoService.exe";
                var cmd = string.Format("create {0} binPath=\"{1}\"", serviceName, exeName);
                ExternalCommandRunner.RunExternalCommand("sc.exe", cmd);

                var sc2 = new ServiceCollector();
                sc2.Execute();

                // Clean up
                cmd = string.Format("delete {0}", serviceName);
                ExternalCommandRunner.RunExternalCommand("sc.exe", cmd);

                BaseCompare bc = new BaseCompare();
                bc.Compare(sc.Results, sc2.Results, FirstRunId, SecondRunId);

                var results = bc.Results;

                Assert.IsTrue(results.ContainsKey((RESULT_TYPE.SERVICE, CHANGE_TYPE.CREATED)));
                Assert.IsTrue(results[(RESULT_TYPE.SERVICE, CHANGE_TYPE.CREATED)].Where(x => x.Identity.Contains("AsaDemoService")).Count() > 0);
            }
        }

        // @TODO ComObject Compare

        /// <summary>
        /// Requires Administrator Priviledges.
        /// </summary>
        [TestMethod]
        public void TestUserCompareWindows()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Assert.IsTrue(AsaHelpers.IsAdmin());
                var FirstRunId = "TestUserCollector-1";
                var SecondRunId = "TestUserCollector-2";

                var uac = new UserAccountCollector();
                uac.Execute();

                var user = System.Guid.NewGuid().ToString().Substring(0, 10);
                var password = "$" + CryptoHelpers.GetRandomString(13);

                var cmd = string.Format("user /add {0} {1}", user, password);
                ExternalCommandRunner.RunExternalCommand("net", cmd);

                var serviceName = System.Guid.NewGuid();

                var uac2 = new UserAccountCollector();
                uac2.Execute();

                cmd = string.Format("user /delete {0}", user);
                ExternalCommandRunner.RunExternalCommand("net", cmd);

                BaseCompare bc = new BaseCompare();
                bc.Compare(uac.Results, uac2.Results, FirstRunId, SecondRunId);

                var results = bc.Results;
                Assert.IsTrue(results.ContainsKey((RESULT_TYPE.USER, CHANGE_TYPE.CREATED)));
                Assert.IsTrue(results[(RESULT_TYPE.USER, CHANGE_TYPE.CREATED)].Where(x => x.Identity.Contains(user)).Count() > 0);
            }
        }

        [TestMethod]
        public void TestFirewallCompareWindows()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Assert.IsTrue(AsaHelpers.IsAdmin());
                var FirstRunId = "TestFirewallCollector-1";
                var SecondRunId = "TestFirewallCollector-2";

                var fwc = new FirewallCollector();
                fwc.Execute();

                var rule = FirewallManager.Instance.CreatePortRule(
                    @"TestFirewallPortRule",
                    FirewallAction.Allow,
                    9999,
                    FirewallProtocol.TCP
                );
                FirewallManager.Instance.Rules.Add(rule);

                rule = FirewallManager.Instance.CreateApplicationRule(
                    @"TestFirewallAppRule",
                    FirewallAction.Allow,
                    @"C:\MyApp.exe"
                );
                rule.Direction = FirewallDirection.Outbound;
                FirewallManager.Instance.Rules.Add(rule);

                var fwc2 = new FirewallCollector();
                fwc2.Execute();

                var rules = FirewallManager.Instance.Rules.Where(r => r.Name == "TestFirewallPortRule");
                foreach (var ruleIn in rules)
                {
                    FirewallManager.Instance.Rules.Remove(ruleIn);
                }

                rules = FirewallManager.Instance.Rules.Where(r => r.Name == "TestFirewallAppRule");
                foreach (var ruleIn in rules)
                {
                    FirewallManager.Instance.Rules.Remove(ruleIn);
                }

                BaseCompare bc = new BaseCompare();
                bc.Compare(fwc.Results, fwc2.Results, FirstRunId, SecondRunId);

                var results = bc.Results;

                Assert.IsTrue(results.ContainsKey((RESULT_TYPE.FIREWALL, CHANGE_TYPE.CREATED)));
                Assert.IsTrue(results[(RESULT_TYPE.FIREWALL, CHANGE_TYPE.CREATED)].Any(x => x.Compare is FirewallObject FWO && FWO.LocalPorts is List<string> ports && ports.Contains("9999")));
                Assert.IsTrue(results[(RESULT_TYPE.FIREWALL, CHANGE_TYPE.CREATED)].Any(x => x.Identity.Contains("MyApp.exe")));
            }
        }
    }
}
