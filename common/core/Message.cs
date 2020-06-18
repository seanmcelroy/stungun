using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace stungun.common.core
{
    public struct Message
    {
        private static readonly RNGCryptoServiceProvider RNG = new RNGCryptoServiceProvider();

        public MessageHeader Header;

        public List<MessageAttribute>? Attributes;

        public static Message CreateBindingRequest()
        {
            var transactionId = new byte[12];
            RNG.GetBytes(transactionId);

            return new Message
            {
                Header = new MessageHeader
                {
                    Type = MessageType.BindingRequest,
                    MessageLength = 0,
                    MagicCookie = 0x2112A442,
                    TransactionId = transactionId
                }
            };
        }

        public static Message Parse(ReadOnlySpan<byte> bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 20)
                throw new ArgumentOutOfRangeException(nameof(bytes), "Messages must be at least 20 bytes long");

            var header = MessageHeader.Parse(bytes.Slice(0, 20));

            var ret = new Message {
                Header = header,
                Attributes = bytes.Length > 20 ? MessageAttribute.ParseList(bytes.Slice(20).ToArray(), header.TransactionId).ToList() : null
            };

            return ret;
        }

        public override string ToString() => $"{Enum.GetName(typeof(MessageType), Header.Type)}";
    }
}
