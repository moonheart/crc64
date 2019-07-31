using System;


namespace crc
{
    static void Main(){
        var buffer = new byte[455452];
        new Random().NextBytes(buffer);
        var tabECMA = Crc64.MakeTable(Crc64.ECMA);
        Crc64.Checksum(buffer, tabECMA);
    }
}
