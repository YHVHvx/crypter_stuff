using System;
using System.IO;
using Bea;

namespace BeaSharp
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Version: " + BeaEngine.Version);
            Console.WriteLine("Revision: " + BeaEngine.Revision);

            UnmanagedBuffer buffer = new UnmanagedBuffer(File.ReadAllBytes("BeaEngine.dll"));

            var disasm = new Disasm();
            disasm.EIP = new IntPtr(buffer.Ptr.ToInt64() + 0x400);

            for(int counter = 0; counter < 100; ++counter)
            {
                int result = BeaEngine.Disasm(disasm);
                
                if (result == (int)BeaConstants.SpecialInfo.UNKNOWN_OPCODE)
                    break;

                Console.WriteLine("0x" + disasm.EIP.ToString("X") + " " + disasm.CompleteInstr);
                disasm.EIP = new IntPtr(disasm.EIP.ToInt64() + result);
            }
        }
    }
}
