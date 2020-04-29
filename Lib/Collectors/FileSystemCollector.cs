﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Mono.Unix;
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects Filesystem Data from the local file system.
    /// </summary>
    public class FileSystemCollector : BaseCollector
    {
        private readonly HashSet<string> roots;

        private readonly bool INCLUDE_CONTENT_HASH = false;

        private readonly bool downloadCloud;
        private readonly bool examineCertificates;
        private readonly bool parallel;

        public FileSystemCollector(CollectCommandOptions opts)
        {
            if (opts is null)
            {
                throw new ArgumentNullException(nameof(opts));
            }
            downloadCloud = opts.DownloadCloud;
            examineCertificates = opts.CertificatesFromFiles;
            parallel = opts.Parallelization;

            roots = new HashSet<string>();
            INCLUDE_CONTENT_HASH = opts.GatherHashes;

            if (!string.IsNullOrEmpty(opts.SelectedDirectories))
            {
                foreach (string path in opts.SelectedDirectories.Split(','))
                {
                    AddRoot(path);
                }
            }

        }

        /// <summary>
        /// Add a root to be collected
        /// </summary>
        /// <param name="root">The path to scan</param>
        public void AddRoot(string root)
        {
            roots.Add(root);
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public override void ExecuteInternal()
        {
            if (!roots.Any())
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    foreach (var driveInfo in DriveInfo.GetDrives())
                    {
                        if (driveInfo.IsReady && driveInfo.DriveType == DriveType.Fixed)
                        {
                            roots.Add(driveInfo.Name);
                        }
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    roots.Add("/");
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    roots.Add("/");
                }
            }

            Action<string> IterateOn = Path =>
            {
                Log.Verbose("Started parsing {0}", Path);
                FileSystemObject obj = FilePathToFileSystemObject(Path, downloadCloud, INCLUDE_CONTENT_HASH);
                if (obj != null)
                {
                    Results.Add(obj);
                    if (examineCertificates &&
                        Path.EndsWith(".cer", StringComparison.CurrentCulture) ||
                        Path.EndsWith(".der", StringComparison.CurrentCulture) ||
                        Path.EndsWith(".p7b", StringComparison.CurrentCulture))
                    {
                        try
                        {
                            using var certificate = new X509Certificate2();
                            certificate.Import(Path);

                            var certObj = new CertificateObject(
                                StoreLocation: StoreLocation.LocalMachine.ToString(),
                                StoreName: StoreName.Root.ToString(),
                                Certificate: new SerializableCertificate(certificate))
                            {
                                Pkcs7 = Convert.ToBase64String(certificate.Export(X509ContentType.Cert))
                            };

                            Results.Add(certObj);
                        }
                        catch (Exception e) when (
                            e is System.Security.Cryptography.CryptographicException
                            || e is ArgumentException)
                        {
                            Log.Verbose($"Could not parse certificate from file: {Path}");
                        }
                    }
                }
                Log.Verbose("Finished parsing {0}", Path);
            };

            foreach (var root in roots)
            {
                Log.Information("{0} root {1}", Strings.Get("Scanning"), root);
                var filePathEnumerable = DirectoryWalker.WalkDirectory(root);

                if (parallel)
                {
                    filePathEnumerable.AsParallel().ForAll(filePath =>
                    {
                        IterateOn(filePath);
                    });
                }
                else
                {
                    foreach (var filePath in filePathEnumerable)
                    {
                        IterateOn(filePath);
                    }
                }
            }
        }

        /// <summary>
        /// Converts a FileSystemInfo into a FileSystemObject by reading in data about the file
        /// </summary>
        /// <param name="fileInfo">A reference to a file on disk.</param>
        /// <param name="downloadCloud">If the file is hosted in the cloud, the user has the option to include cloud files or not.</param>
        /// <param name="includeContentHash">If we should generate a hash of the file.</param>
        /// <returns></returns>
        public static FileSystemObject FilePathToFileSystemObject(string path, bool downloadCloud = false, bool includeContentHash = false)
        {
            FileSystemObject obj = new FileSystemObject(path);

            // Get Owner/Group
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    var fileSecurity = new FileSecurity(path, AccessControlSections.All);
                    IdentityReference oid = fileSecurity.GetOwner(typeof(SecurityIdentifier));
                    IdentityReference gid = fileSecurity.GetGroup(typeof(SecurityIdentifier));

                    obj.Owner = AsaHelpers.SidToName(oid);
                    obj.Group = AsaHelpers.SidToName(gid);

                    var rules = fileSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));
                    foreach (FileSystemAccessRule? rule in rules)
                    {
                        if (rule != null)
                        {
                            string name = AsaHelpers.SidToName(rule.IdentityReference);

                            obj.Permissions = new Dictionary<string, string>();

                            foreach (var permission in rule.FileSystemRights.ToString().Split(','))
                            {
                                if (obj.Permissions.ContainsKey(name))
                                {
                                    obj.Permissions[name] = $"{obj.Permissions[name]},{permission}";
                                }
                                else
                                {
                                    obj.Permissions.Add(name, permission);
                                }
                            }
                        }
                    }
                }
                catch (Exception e) when (
                    e is ArgumentException
                    || e is ArgumentNullException
                    || e is DirectoryNotFoundException
                    || e is FileNotFoundException
                    || e is IOException
                    || e is NotSupportedException
                    || e is PlatformNotSupportedException
                    || e is PathTooLongException
                    || e is PrivilegeNotHeldException
                    || e is SystemException
                    || e is UnauthorizedAccessException)
                {
                    Log.Verbose($"Error instantiating FileSecurity object {obj.Path} {e.GetType().ToString()}");
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                try
                {
                    var file = new UnixSymbolicLinkInfo(path);
                    obj.Owner = file.OwnerUser.UserName;
                    obj.Group = file.OwnerGroup.GroupName;
                    obj.SetGid = file.IsSetGroup;
                    obj.SetUid = file.IsSetUser;

                    obj.Permissions = new Dictionary<string, string>();
                    if (file.FileAccessPermissions.ToString().Equals("AllPermissions", StringComparison.InvariantCulture))
                    {
                        obj.Permissions.Add("User", "Read,Write,Execute");
                        obj.Permissions.Add("Group", "Read,Write,Execute");
                        obj.Permissions.Add("Other", "Read,Write,Execute");
                    }
                    else
                    {
                        var keys = new List<string>() { "User", "Group", "Other" };
                        var splits = file.FileAccessPermissions.ToString().Split(',').Select(x => x.Trim());
                        foreach (var key in keys)
                        {
                            foreach (var permission in splits.Where((x) => x.StartsWith(key, StringComparison.InvariantCulture)))
                            {
                                if (permission.Contains("ReadWriteExecute", StringComparison.InvariantCulture))
                                {
                                    obj.Permissions.Add(key, "Read,Write,Execute");
                                }
                                else
                                {
                                    if (obj.Permissions.ContainsKey(key))
                                    {
                                        obj.Permissions[key] = $"{obj.Permissions[key]},{permission.Trim().Substring(key.Length)}";
                                    }
                                    else
                                    {
                                        obj.Permissions.Add(key, permission.Trim().Substring(key.Length));
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception e) when (
                    e is ArgumentNullException
                    || e is ArgumentException
                    || e is InvalidOperationException)
                {
                    Log.Debug($"Failed to get permissions for {path} {e.GetType().ToString()}");
                }
            }


            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    if (Directory.Exists(path))
                    {
                        var fileInfo = new DirectoryInfo(path);
                        if (fileInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
                        {
                            obj.IsLink = true;
                            obj.Target = NativeMethods.GetFinalPathName(path);
                        }
                        else
                        {
                            obj.IsDirectory = true;
                        }
                    }
                    else
                    {
                        var fileInfo = new FileInfo(path);
                        var size = (ulong)fileInfo.Length;
                        obj.Size = size;
                        if (WindowsFileSystemUtils.IsLocal(obj.Path) || downloadCloud)
                        {
                            if (includeContentHash)
                            {
                                obj.ContentHash = FileSystemUtils.GetFileHash(fileInfo);
                            }

                            obj.IsExecutable = FileSystemUtils.IsExecutable(obj.Path, size);

                            if (obj.IsExecutable != null && (bool)obj.IsExecutable)
                            {
                                obj.SignatureStatus = WindowsFileSystemUtils.GetSignatureStatus(path);
                                obj.Characteristics = WindowsFileSystemUtils.GetDllCharacteristics(path);
                            }
                        }
                    }
                }
                else
                {
                    UnixSymbolicLinkInfo i = new UnixSymbolicLinkInfo(path);
                    obj.FileType = i.FileType.ToString();
                    obj.Size = (ulong)i.Length;
                    obj.IsDirectory = false;
                    switch (i.FileType)
                    {
                        case FileTypes.SymbolicLink:
                            obj.IsLink = true;
                            obj.Target = i.ContentsPath;
                            break;
                        case FileTypes.Fifo:
                        case FileTypes.Socket:
                        case FileTypes.BlockDevice:
                        case FileTypes.CharacterDevice:
                        case FileTypes.Directory:
                            obj.IsDirectory = true;
                            break;
                        case FileTypes.RegularFile:
                            if (includeContentHash)
                            {
                                obj.ContentHash = FileSystemUtils.GetFileHash(path);
                            }
                            obj.IsExecutable = FileSystemUtils.IsExecutable(obj.Path, obj.Size);
                            break;
                    }
                }

                obj.LastModified = File.GetLastWriteTimeUtc(path);
                obj.Created = File.GetCreationTimeUtc(path);
            }
            catch (Exception e) when (
                e is ArgumentNullException ||
                e is SecurityException ||
                e is ArgumentException ||
                e is UnauthorizedAccessException ||
                e is PathTooLongException ||
                e is NotSupportedException ||
                e is InvalidOperationException)
            {
                Log.Verbose("Failed to create FileInfo from File at {0} {1}", path, e.GetType().ToString());
            }
            catch (Exception e)
            {
                Log.Debug("Should be caught in DirectoryWalker {0}", e.GetType().ToString());
            }

            return obj;
        }
    }
}
