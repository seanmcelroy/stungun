using System.Linq;
using Xunit;
using stungun.common.core;

namespace stungun.common.tests
{
    public class ErrorHandlingTests
    {
        #region ErrorCodeAttribute Tests

        [Fact]
        public void ErrorCodeAttribute_CreateWithCode_SetsPropertiesCorrectly()
        {
            var attr = new ErrorCodeAttribute(401, "Unauthorized");

            Assert.Equal(AttributeType.ErrorCode, attr.Type);
            Assert.Equal(401, attr.ErrorCode);
            Assert.Equal(4, attr.ErrorClass);
            Assert.Equal(1, attr.ErrorNumber);
            Assert.Equal("Unauthorized", attr.ReasonPhrase);
        }

        [Fact]
        public void ErrorCodeAttribute_SetErrorCode_UpdatesClassAndNumber()
        {
            var attr = new ErrorCodeAttribute();
            attr.ErrorCode = 500;

            Assert.Equal(500, attr.ErrorCode);
            Assert.Equal(5, attr.ErrorClass);
            Assert.Equal(0, attr.ErrorNumber);
        }

        [Theory]
        [InlineData(300, 3, 0)]
        [InlineData(400, 4, 0)]
        [InlineData(401, 4, 1)]
        [InlineData(420, 4, 20)]
        [InlineData(438, 4, 38)]
        [InlineData(500, 5, 0)]
        [InlineData(699, 6, 99)]
        public void ErrorCodeAttribute_ErrorCodeValues_CorrectClassAndNumber(int code, int expectedClass, int expectedNumber)
        {
            var attr = new ErrorCodeAttribute();
            attr.ErrorCode = code;

            Assert.Equal(expectedClass, attr.ErrorClass);
            Assert.Equal(expectedNumber, attr.ErrorNumber);
            Assert.Equal(code, attr.ErrorCode);
        }

        [Fact]
        public void ErrorCodeAttribute_Serialize_ProducesValidBytes()
        {
            var attr = new ErrorCodeAttribute(420, "Unknown Attribute");
            var bytes = attr.ToByteArray();

            // Type (2 bytes) + Length (2 bytes) + Reserved (2 bytes) + Class (1 byte) + Number (1 byte) + Reason
            Assert.True(bytes.Length >= 8);

            // Check type is ERROR-CODE (0x0009)
            Assert.Equal(0x00, bytes[0]);
            Assert.Equal(0x09, bytes[1]);

            // Check class (byte index 6, lower 3 bits)
            Assert.Equal(4, bytes[6] & 0x07);

            // Check number (byte index 7)
            Assert.Equal(20, bytes[7]);
        }

        [Fact]
        public void ErrorCodeAttribute_RoundTrip_PreservesData()
        {
            var original = new ErrorCodeAttribute(438, "Stale Nonce");
            var bytes = original.ToByteArray();

            // Parse the bytes back
            var parsed = MessageAttribute.Parse(bytes);
            Assert.Equal(AttributeType.ErrorCode, parsed.Type);

            var typedParsed = ErrorCodeAttribute.FromGenericAttribute(parsed);
            Assert.Equal(438, typedParsed.ErrorCode);
            Assert.Equal(4, typedParsed.ErrorClass);
            Assert.Equal(38, typedParsed.ErrorNumber);
            Assert.Equal("Stale Nonce", typedParsed.ReasonPhrase);
        }

        [Fact]
        public void ErrorCodeAttribute_EmptyReasonPhrase_Works()
        {
            var attr = new ErrorCodeAttribute(500, "");
            var bytes = attr.ToByteArray();

            var parsed = MessageAttribute.Parse(bytes);
            var typedParsed = ErrorCodeAttribute.FromGenericAttribute(parsed);

            Assert.Equal(500, typedParsed.ErrorCode);
            Assert.Equal("", typedParsed.ReasonPhrase);
        }

        #endregion

        #region UnknownAttributesAttribute Tests

        [Fact]
        public void UnknownAttributesAttribute_Create_SetsTypeCorrectly()
        {
            var attr = new UnknownAttributesAttribute();
            Assert.Equal(AttributeType.UnknownAttributes, attr.Type);
        }

        [Fact]
        public void UnknownAttributesAttribute_AddTypes_StoresCorrectly()
        {
            var attr = new UnknownAttributesAttribute(new ushort[] { 0x0010, 0x0011, 0x0012 });

            Assert.Equal(3, attr.UnknownTypes.Count);
            Assert.Equal(0x0010, attr.UnknownTypes[0]);
            Assert.Equal(0x0011, attr.UnknownTypes[1]);
            Assert.Equal(0x0012, attr.UnknownTypes[2]);
        }

        [Fact]
        public void UnknownAttributesAttribute_Serialize_ProducesValidBytes()
        {
            var attr = new UnknownAttributesAttribute(new ushort[] { 0x0010, 0x0011 });
            var bytes = attr.ToByteArray();

            // Type (2 bytes) + Length (2 bytes) + 2 attribute types (4 bytes)
            Assert.Equal(8, bytes.Length);

            // Check type is UNKNOWN-ATTRIBUTES (0x000A)
            Assert.Equal(0x00, bytes[0]);
            Assert.Equal(0x0A, bytes[1]);

            // Check length is 4
            Assert.Equal(0x00, bytes[2]);
            Assert.Equal(0x04, bytes[3]);

            // Check first unknown type (0x0010)
            Assert.Equal(0x00, bytes[4]);
            Assert.Equal(0x10, bytes[5]);

            // Check second unknown type (0x0011)
            Assert.Equal(0x00, bytes[6]);
            Assert.Equal(0x11, bytes[7]);
        }

        [Fact]
        public void UnknownAttributesAttribute_RoundTrip_PreservesData()
        {
            var original = new UnknownAttributesAttribute(new ushort[] { 0x0010, 0x0020, 0x0030 });
            var bytes = original.ToByteArray();

            var parsed = MessageAttribute.Parse(bytes);
            Assert.Equal(AttributeType.UnknownAttributes, parsed.Type);

            var typedParsed = UnknownAttributesAttribute.FromGenericAttribute(parsed);
            Assert.Equal(3, typedParsed.UnknownTypes.Count);
            Assert.Equal(0x0010, typedParsed.UnknownTypes[0]);
            Assert.Equal(0x0020, typedParsed.UnknownTypes[1]);
            Assert.Equal(0x0030, typedParsed.UnknownTypes[2]);
        }

        [Fact]
        public void UnknownAttributesAttribute_OddCount_PaddedTo4ByteBoundary()
        {
            // 3 attributes = 6 bytes, should be padded to 8 bytes
            var attr = new UnknownAttributesAttribute(new ushort[] { 0x0010, 0x0011, 0x0012 });
            var bytes = attr.ToByteArray();

            // Type (2) + Length (2) + padded value (8) = 12 bytes
            Assert.Equal(12, bytes.Length);

            // Length field should be 6 (actual data, not padded)
            Assert.Equal(0x00, bytes[2]);
            Assert.Equal(0x06, bytes[3]);
        }

        #endregion

        #region StunErrorCodes Tests

        [Fact]
        public void StunErrorCodes_GetReasonPhrase_ReturnsCorrectPhrases()
        {
            Assert.Equal("Try Alternate", StunErrorCodes.GetReasonPhrase(300));
            Assert.Equal("Bad Request", StunErrorCodes.GetReasonPhrase(400));
            Assert.Equal("Unauthorized", StunErrorCodes.GetReasonPhrase(401));
            Assert.Equal("Unknown Attribute", StunErrorCodes.GetReasonPhrase(420));
            Assert.Equal("Stale Nonce", StunErrorCodes.GetReasonPhrase(438));
            Assert.Equal("Server Error", StunErrorCodes.GetReasonPhrase(500));
        }

        [Fact]
        public void StunErrorCodes_GetReasonPhrase_UnknownCode_ReturnsUnknownError()
        {
            Assert.Equal("Unknown Error", StunErrorCodes.GetReasonPhrase(999));
        }

        [Fact]
        public void StunErrorCodes_CreateErrorAttribute_CreatesCorrectAttribute()
        {
            var attr = StunErrorCodes.CreateErrorAttribute(401);

            Assert.Equal(401, attr.ErrorCode);
            Assert.Equal("Unauthorized", attr.ReasonPhrase);
        }

        [Fact]
        public void StunErrorCodes_CreateErrorAttribute_WithCustomReason()
        {
            var attr = StunErrorCodes.CreateErrorAttribute(400, "Custom bad request message");

            Assert.Equal(400, attr.ErrorCode);
            Assert.Equal("Custom bad request message", attr.ReasonPhrase);
        }

        #endregion

        #region Message Parsing with Errors Tests

        [Fact]
        public void ParseListWithResult_NoUnknownAttributes_EmptyList()
        {
            // A simple MAPPED-ADDRESS attribute
            // Type: 0x0001, Length: 8, Family: IPv4, Port: 0x1234, IP: 192.168.1.1
            var attrBytes = new byte[]
            {
                0x00, 0x01,             // Type: MAPPED-ADDRESS
                0x00, 0x08,             // Length: 8
                0x00, 0x01,             // Reserved + Family (IPv4)
                0x12, 0x34,             // Port
                0xC0, 0xA8, 0x01, 0x01  // IP: 192.168.1.1
            };

            var transactionId = new byte[12];
            var result = MessageAttribute.ParseListWithResult(attrBytes, transactionId);

            Assert.False(result.HasUnknownComprehensionRequired);
            Assert.Empty(result.UnknownComprehensionRequiredTypes);
            Assert.Single(result.Attributes);
        }

        [Fact]
        public void ParseListWithResult_UnknownComprehensionRequired_ReportsType()
        {
            // Unknown comprehension-required attribute (type 0x0099)
            var attrBytes = new byte[]
            {
                0x00, 0x99,             // Type: Unknown (0x0099 < 0x8000 = comprehension-required)
                0x00, 0x04,             // Length: 4
                0x01, 0x02, 0x03, 0x04  // Value
            };

            var transactionId = new byte[12];
            var result = MessageAttribute.ParseListWithResult(attrBytes, transactionId);

            Assert.True(result.HasUnknownComprehensionRequired);
            Assert.Single(result.UnknownComprehensionRequiredTypes);
            Assert.Equal(0x0099, result.UnknownComprehensionRequiredTypes[0]);
        }

        [Fact]
        public void ParseListWithResult_UnknownComprehensionOptional_NoError()
        {
            // Unknown comprehension-optional attribute (type 0x8099)
            var attrBytes = new byte[]
            {
                0x80, 0x99,             // Type: Unknown (0x8099 >= 0x8000 = comprehension-optional)
                0x00, 0x04,             // Length: 4
                0x01, 0x02, 0x03, 0x04  // Value
            };

            var transactionId = new byte[12];
            var result = MessageAttribute.ParseListWithResult(attrBytes, transactionId);

            Assert.False(result.HasUnknownComprehensionRequired);
            Assert.Empty(result.UnknownComprehensionRequiredTypes);
            // The attribute is skipped, so no attributes in the result
            Assert.Empty(result.Attributes);
        }

        [Fact]
        public void ParseBindingErrorWithErrorCode()
        {
            // Manually construct a BindingError message with ERROR-CODE attribute
            // Header: BindingError (0x0111), Length: 16, Magic Cookie, Transaction ID
            // ERROR-CODE: 420 Unknown Attribute

            var errorAttr = new ErrorCodeAttribute(420, "Unknown Attribute");
            var errorBytes = errorAttr.ToByteArray();

            var header = new byte[]
            {
                0x01, 0x11,             // Type: BindingError
                0x00, (byte)errorBytes.Length,  // Length
                0x21, 0x12, 0xA4, 0x42, // Magic Cookie
                0x01, 0x02, 0x03, 0x04, // Transaction ID (12 bytes)
                0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C
            };

            var fullMessage = header.Concat(errorBytes).ToArray();
            var msg = Message.Parse(fullMessage);

            Assert.Equal(MessageType.BindingError, msg.Header.Type);
            Assert.NotNull(msg.Attributes);
            Assert.Single(msg.Attributes);

            var parsedError = msg.Attributes[0] as ErrorCodeAttribute;
            Assert.NotNull(parsedError);
            Assert.Equal(420, parsedError.ErrorCode);
            Assert.Equal("Unknown Attribute", parsedError.ReasonPhrase);
        }

        #endregion
    }
}
