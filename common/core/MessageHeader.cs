using System;
using System.Linq;

namespace stungun.common.core
{
    public struct MessageHeader
    {
        public MessageType Type;
        public ushort MessageLength;
        public uint MagicCookie;
        public byte[] TransactionId;

        public static MessageHeader Parse(ReadOnlySpan<byte> bytes)
        {
            if (bytes.IsEmpty)
                throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 20)
                throw new ArgumentOutOfRangeException(nameof(bytes), "Message headers must be at least 20 bytes long");

            var ba = bytes.ToArray();

            var mType = BitConverter.ToUInt16(new byte[] { bytes[1], bytes[0] });
            var mLen = BitConverter.ToUInt16(new byte[] { bytes[3], bytes[2] });

            var ret = new MessageHeader
            {
                Type = (MessageType)mType,
                MessageLength = mLen,
                MagicCookie = BitConverter.ToUInt32(ba, 4),
                TransactionId = bytes.Slice(8, 12).ToArray()
            };

            return ret;
        }

        public void PrintDebug()
        {
            Console.WriteLine($" 0                   1                   2                   3   ");
            Console.WriteLine($" 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 ");
            Console.WriteLine($"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
            Console.WriteLine($"|0 0| STUN Message Type = 0x{BitConverter.GetBytes((ushort)Type).Reverse().Select(b => $"{b:x2}").Aggregate((c, n) => c + n).PadRight(4, ' ')}| MsgLen = {MessageLength.ToString().PadRight(21, ' ')}|");
            Console.WriteLine($"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
            Console.WriteLine($"|                  Magic Cookie = 0x{BitConverter.GetBytes(MagicCookie).Reverse().Select(b => $"{b:x2}").Aggregate((c, n) => c + n).PadRight(28, ' ')}|");
            Console.WriteLine($"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
            Console.WriteLine($"| Transaction ID (96 bits) {TransactionId.Take(4).Select(b => $"{b:x2} ").Aggregate((c, n) => c + n).PadRight(37, ' ')}|");
            Console.WriteLine($"|                          {TransactionId.Skip(4).Take(4).Select(b => $"{b:x2} ").Aggregate((c, n) => c + n).PadRight(37, ' ')}|");
            Console.WriteLine($"|                          {TransactionId.Skip(8).Take(4).Select(b => $"{b:x2} ").Aggregate((c, n) => c + n).PadRight(37, ' ')}|");
            Console.WriteLine($"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
        }
    }
}
