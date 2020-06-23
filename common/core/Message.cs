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

        public IReadOnlyList<MessageAttribute>? Attributes;

        public static Message CreateBindingRequest(IList<MessageAttribute>? attributes, byte[]? customTransactionId)
        {
            byte[] transactionId;
            if (customTransactionId == null)
            {
                transactionId = new byte[12];
                RNG.GetBytes(transactionId);
            }
            else
            {
                if (customTransactionId.Length != 12)
                    throw new ArgumentOutOfRangeException(nameof(customTransactionId), customTransactionId, "TransactionID must be 12 bytes");
                transactionId = customTransactionId;
            }

            var attributeList = attributes?.ToList().AsReadOnly();
            var messageLength = attributeList?.Sum(a => a.Bytes.Count) ?? 0;

            return new Message
            {
                Header = new MessageHeader
                {
                    Type = MessageType.BindingRequest,
                    MessageLength = (ushort)messageLength,
                    MagicCookie = 0x2112A442,
                    TransactionId = transactionId
                },
                Attributes = attributeList
            };
        }

        public static Message Parse(ReadOnlySpan<byte> bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 20)
                throw new ArgumentOutOfRangeException(nameof(bytes), "Messages must be at least 20 bytes long");

            var header = MessageHeader.Parse(bytes.Slice(0, 20));

            var ret = new Message
            {
                Header = header,
                Attributes = bytes.Length > 20 ? MessageAttribute.ParseList(bytes.Slice(20).ToArray(), header.TransactionId).ToList() : null
            };

            return ret;
        }

        public void PrintDebug()
        {
            this.Header.PrintDebug();
            if (this.Attributes != null)
                foreach (var attr in this.Attributes)
                    attr.PrintDebug();
        }

        public override string ToString() => $"{Enum.GetName(typeof(MessageType), Header.Type)}";
    }
}
