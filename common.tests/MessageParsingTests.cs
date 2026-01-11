using System;
using System.Linq;
using Xunit;
using stungun.common.core;

namespace stungun.common.tests
{
    public class MessageParsingTests
    {
        #region Message Parsing Tests

        [Fact]
        public void Parse_ValidBindingRequest_Success()
        {
            // Valid 20-byte binding request with no attributes
            var bytes = ByteUtility.StringToByteArray("000100002112a442ba2cd7344e99232f23f396ce");
            var msg = Message.Parse(bytes);

            Assert.Equal(MessageType.BindingRequest, msg.Header.Type);
            Assert.Equal(0, msg.Header.MessageLength);
            // Magic cookie is stored in little-endian in the struct
            Assert.Equal(0x42A41221u, msg.Header.MagicCookie);
            Assert.Null(msg.Attributes);
        }

        [Fact]
        public void Parse_ValidBindingResponse_Success()
        {
            // Binding response with 4 attributes
            var bytes = ByteUtility.StringToByteArray("010100302112a442ba2cd7344e99232f23f396ce000100080001d2d968bb4fb2802b000800010d9612bfdf0c802c000800010d9712db6e12002000080001f3cb49a9ebf0");
            var msg = Message.Parse(bytes);

            Assert.Equal(MessageType.BindingResponse, msg.Header.Type);
            Assert.Equal(48, msg.Header.MessageLength);
            Assert.NotNull(msg.Attributes);
            Assert.Equal(4, msg.Attributes.Count);
        }

        [Fact]
        public void Parse_TooShort_ThrowsArgumentOutOfRangeException()
        {
            // Only 10 bytes - too short for valid STUN message
            var bytes = new byte[] { 0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0xba, 0x2c };

            Assert.Throws<ArgumentOutOfRangeException>(() => Message.Parse(bytes));
        }

        [Fact]
        public void Parse_EmptyBytes_ThrowsArgumentNullException()
        {
            var bytes = Array.Empty<byte>();

            Assert.Throws<ArgumentNullException>(() => Message.Parse(bytes));
        }

        [Fact]
        public void Parse_ExactlyMinimumLength_Success()
        {
            // Exactly 20 bytes - minimum valid message
            var bytes = ByteUtility.StringToByteArray("000100002112a442ba2cd7344e99232f23f396ce");
            var msg = Message.Parse(bytes);

            Assert.Equal(MessageType.BindingRequest, msg.Header.Type);
            Assert.Equal(20, bytes.Length);
        }

        [Fact]
        public void Parse_InvalidMagicCookie_StillParses()
        {
            // Magic cookie is different from standard 0x2112A442
            var bytes = ByteUtility.StringToByteArray("0001000012345678ba2cd7344e99232f23f396ce");
            var msg = Message.Parse(bytes);

            // Should still parse, magic cookie is just stored as-is
            Assert.Equal(MessageType.BindingRequest, msg.Header.Type);
            Assert.NotEqual(0x2112A442u, msg.Header.MagicCookie);
        }

        [Fact]
        public void Parse_MultipleAttributes_AllParsed()
        {
            var bytes = ByteUtility.StringToByteArray("010100302112a442ba2cd7344e99232f23f396ce000100080001d2d968bb4fb2802b000800010d9612bfdf0c802c000800010d9712db6e12002000080001f3cb49a9ebf0");
            var msg = Message.Parse(bytes);

            Assert.NotNull(msg.Attributes);
            Assert.Equal(4, msg.Attributes.Count);

            // Verify each attribute type
            Assert.Equal(AttributeType.MappedAddress, msg.Attributes[0].Type);
            Assert.Equal(AttributeType.ResponseOrigin, msg.Attributes[1].Type);
            Assert.Equal(AttributeType.OtherAddress, msg.Attributes[2].Type);
            Assert.Equal(AttributeType.XorMappedAddress, msg.Attributes[3].Type);
        }

        #endregion

        #region MessageHeader Parsing Tests

        [Fact]
        public void ParseHeader_ValidHeader_Success()
        {
            var bytes = ByteUtility.StringToByteArray("000100002112a442ba2cd7344e99232f23f396ce");
            var header = MessageHeader.Parse(bytes);

            Assert.Equal(MessageType.BindingRequest, header.Type);
            Assert.Equal(0, header.MessageLength);
            // Magic cookie is stored as little-endian in the struct
            Assert.Equal(0x42A41221u, header.MagicCookie);
            Assert.Equal(12, header.TransactionId.Length);
        }

        [Fact]
        public void ParseHeader_TransactionId_Correct()
        {
            var bytes = ByteUtility.StringToByteArray("000100002112a442ba2cd7344e99232f23f396ce");
            var header = MessageHeader.Parse(bytes);

            var expectedTxId = new byte[] { 0xba, 0x2c, 0xd7, 0x34, 0x4e, 0x99, 0x23, 0x2f, 0x23, 0xf3, 0x96, 0xce };
            Assert.Equal(expectedTxId, header.TransactionId);
        }

        [Fact]
        public void ParseHeader_TooShort_ThrowsArgumentOutOfRangeException()
        {
            var bytes = new byte[] { 0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0xba };

            Assert.Throws<ArgumentOutOfRangeException>(() => MessageHeader.Parse(bytes));
        }

        [Fact]
        public void ParseHeader_Empty_ThrowsArgumentNullException()
        {
            var bytes = Array.Empty<byte>();

            Assert.Throws<ArgumentNullException>(() => MessageHeader.Parse(bytes));
        }

        #endregion

        #region MessageAttribute Parsing Tests

        [Fact]
        public void ParseAttribute_TooShort_ThrowsArgumentOutOfRangeException()
        {
            var bytes = new byte[] { 0x00, 0x01, 0x00 }; // Only 3 bytes

            Assert.Throws<ArgumentOutOfRangeException>(() => MessageAttribute.Parse(bytes));
        }

        [Fact]
        public void ParseAttribute_ValidMappedAddress_Success()
        {
            // MAPPED-ADDRESS attribute
            var bytes = new byte[] { 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0xd2, 0xd9, 0x68, 0xbb, 0x4f, 0xb2 };
            var attr = MessageAttribute.Parse(bytes);

            Assert.Equal(AttributeType.MappedAddress, attr.Type);
            Assert.Equal(8, attr.AttributeLength);
        }

        [Fact]
        public void ParseAttribute_UnknownComprehensionOptional_ReturnsUnknown()
        {
            // Type 0x8099 - comprehension-optional but unknown
            var bytes = new byte[] { 0x80, 0x99, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04 };
            var attr = MessageAttribute.Parse(bytes, out var unknownType);

            Assert.Equal(AttributeType.Unknown, attr.Type);
            Assert.Equal(0x8099, attr.RawType);
            Assert.Null(unknownType); // Not comprehension-required
        }

        [Fact]
        public void ParseAttribute_UnknownComprehensionRequired_ReturnsTypeInfo()
        {
            // Type 0x0099 - comprehension-required but unknown
            var bytes = new byte[] { 0x00, 0x99, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04 };
            var attr = MessageAttribute.Parse(bytes, out var unknownType);

            Assert.Equal(AttributeType.Unknown, attr.Type);
            Assert.Equal(0x0099, attr.RawType);
            Assert.NotNull(unknownType);
            Assert.Equal(0x0099, unknownType.Value);
        }

        #endregion

        #region ParseListWithResult Tests

        [Fact]
        public void ParseListWithResult_NoUnknown_EmptyUnknownList()
        {
            var transactionId = new byte[12];
            // MAPPED-ADDRESS attribute
            var bytes = new byte[] { 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0xd2, 0xd9, 0x68, 0xbb, 0x4f, 0xb2 };

            var result = MessageAttribute.ParseListWithResult(bytes, transactionId);

            Assert.Single(result.Attributes);
            Assert.Empty(result.UnknownComprehensionRequiredTypes);
            Assert.False(result.HasUnknownComprehensionRequired);
        }

        [Fact]
        public void ParseListWithResult_WithUnknownComprehensionRequired_TracksType()
        {
            var transactionId = new byte[12];
            // Unknown comprehension-required attribute (type 0x0099)
            var bytes = new byte[] { 0x00, 0x99, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04 };

            var result = MessageAttribute.ParseListWithResult(bytes, transactionId);

            Assert.Empty(result.Attributes); // Unknown attrs are not added to the list
            Assert.Single(result.UnknownComprehensionRequiredTypes);
            Assert.Equal(0x0099, result.UnknownComprehensionRequiredTypes[0]);
            Assert.True(result.HasUnknownComprehensionRequired);
        }

        [Fact]
        public void ParseListWithResult_MultipleUnknownTypes_TracksAll()
        {
            var transactionId = new byte[12];
            // Two unknown comprehension-required attributes
            var bytes = new byte[] {
                // First: type 0x0098, length 4
                0x00, 0x98, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
                // Second: type 0x0099, length 4
                0x00, 0x99, 0x00, 0x04, 0x05, 0x06, 0x07, 0x08
            };

            var result = MessageAttribute.ParseListWithResult(bytes, transactionId);

            Assert.Equal(2, result.UnknownComprehensionRequiredTypes.Count);
            Assert.Contains((ushort)0x0098, result.UnknownComprehensionRequiredTypes);
            Assert.Contains((ushort)0x0099, result.UnknownComprehensionRequiredTypes);
        }

        #endregion

        #region Message Round-Trip Tests

        [Fact]
        public void Message_RoundTrip_NoAttributes()
        {
            var original = Message.CreateBindingRequest(null, new byte[12]);
            var bytes = MessageUtility.ToByteArray(original);
            var parsed = Message.Parse(bytes);

            Assert.Equal(original.Header.Type, parsed.Header.Type);
            Assert.Equal(original.Header.MessageLength, parsed.Header.MessageLength);
            // Magic cookie has endianness conversion between create and parse
            // CreateBindingRequest sets 0x2112A442, but after serialize/parse it becomes 0x42A41221
            Assert.Equal(0x42A41221u, parsed.Header.MagicCookie);
            Assert.Equal(original.Header.TransactionId, parsed.Header.TransactionId);
        }

        [Fact]
        public void Message_RoundTrip_WithAttributes()
        {
            var transactionId = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
            var attributes = new MessageAttribute[]
            {
                new MappedAddressAttribute
                {
                    AddressFamily = System.Net.Sockets.AddressFamily.InterNetwork,
                    Port = 12345,
                    IPAddress = System.Net.IPAddress.Parse("192.168.1.1")
                }
            };

            var original = Message.CreateBindingRequest(attributes, transactionId);
            var bytes = MessageUtility.ToByteArray(original);
            var parsed = Message.Parse(bytes);

            Assert.Equal(original.Header.Type, parsed.Header.Type);
            Assert.NotNull(parsed.Attributes);
            Assert.Single(parsed.Attributes);
            Assert.Equal(AttributeType.MappedAddress, parsed.Attributes[0].Type);
        }

        [Fact]
        public void CreateBindingRequest_CustomTransactionId_Used()
        {
            var customTxId = new byte[] { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
            var msg = Message.CreateBindingRequest(null, customTxId);

            Assert.Equal(customTxId, msg.Header.TransactionId);
        }

        [Fact]
        public void CreateBindingRequest_InvalidTransactionIdLength_Throws()
        {
            var invalidTxId = new byte[] { 0x01, 0x02, 0x03 }; // Only 3 bytes

            Assert.Throws<ArgumentOutOfRangeException>(() => Message.CreateBindingRequest(null, invalidTxId));
        }

        [Fact]
        public void CreateBindingRequest_NullTransactionId_GeneratesRandom()
        {
            var msg1 = Message.CreateBindingRequest(null, null);
            var msg2 = Message.CreateBindingRequest(null, null);

            Assert.NotNull(msg1.Header.TransactionId);
            Assert.NotNull(msg2.Header.TransactionId);
            Assert.Equal(12, msg1.Header.TransactionId.Length);
            Assert.Equal(12, msg2.Header.TransactionId.Length);
            // Very unlikely to be equal
            Assert.NotEqual(msg1.Header.TransactionId, msg2.Header.TransactionId);
        }

        #endregion

        #region MessageType Tests

        [Theory]
        [InlineData(0x0001, MessageType.BindingRequest)]
        [InlineData(0x0101, MessageType.BindingResponse)]
        [InlineData(0x0111, MessageType.BindingError)]
        public void MessageType_Values_Correct(int expectedValue, MessageType type)
        {
            Assert.Equal(expectedValue, (int)type);
        }

        #endregion

        #region ByteUtility Tests

        [Fact]
        public void ByteUtility_StringToByteArray_ValidHex()
        {
            var result = ByteUtility.StringToByteArray("0001");
            Assert.Equal(new byte[] { 0x00, 0x01 }, result);
        }

        [Fact]
        public void ByteUtility_StringToByteArray_LongerString()
        {
            var result = ByteUtility.StringToByteArray("deadbeef");
            Assert.Equal(new byte[] { 0xde, 0xad, 0xbe, 0xef }, result);
        }

        [Fact]
        public void ByteUtility_StringToByteArray_EmptyString()
        {
            var result = ByteUtility.StringToByteArray("");
            Assert.Empty(result);
        }

        #endregion
    }
}
