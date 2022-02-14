using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace KrbRelay.Com
{
    internal static class ComUtils
    {
        [DllImport("ole32.dll")]
        private static extern int CreateObjrefMoniker(
                IntPtr punk,
                out IMoniker ppmk);

        [DllImport("ole32.dll")]
        private static extern int CreateBindCtx(
              int reserved,
              out IBindCtx ppbc
            );

        public static byte[] GetMarshalledObject(object o)
        {
            IMoniker mk;

            CreateObjrefMoniker(Marshal.GetIUnknownForObject(o), out mk);

            IBindCtx bc;

            CreateBindCtx(0, out bc);

            string name;

            mk.GetDisplayName(bc, null, out name);

            return Convert.FromBase64String(name.Substring(7).TrimEnd(':'));
        }
    }
}