namespace stungun.common.core
{
    /// <summary>
    /// Standard STUN error codes as defined in RFC 5389 Section 15.6.
    /// </summary>
    public static class StunErrorCodes
    {
        /// <summary>
        /// 300 Try Alternate: The client should contact an alternate server for this request.
        /// This error response MUST only be sent if the request included a USERNAME attribute
        /// and a valid MESSAGE-INTEGRITY attribute.
        /// </summary>
        public const int TryAlternate = 300;
        public const string TryAlternateReason = "Try Alternate";

        /// <summary>
        /// 400 Bad Request: The request was malformed. The client SHOULD NOT retry the
        /// request without modification from the previous attempt.
        /// </summary>
        public const int BadRequest = 400;
        public const string BadRequestReason = "Bad Request";

        /// <summary>
        /// 401 Unauthorized: The request did not contain the correct credentials to proceed.
        /// The client should retry the request with proper credentials.
        /// </summary>
        public const int Unauthorized = 401;
        public const string UnauthorizedReason = "Unauthorized";

        /// <summary>
        /// 420 Unknown Attribute: The server received a STUN packet containing a
        /// comprehension-required attribute that it did not understand.
        /// </summary>
        public const int UnknownAttribute = 420;
        public const string UnknownAttributeReason = "Unknown Attribute";

        /// <summary>
        /// 438 Stale Nonce: The NONCE used by the client was no longer valid.
        /// The client should retry with the NONCE provided in the response.
        /// </summary>
        public const int StaleNonce = 438;
        public const string StaleNonceReason = "Stale Nonce";

        /// <summary>
        /// 500 Server Error: The server has suffered a temporary error.
        /// The client should try again.
        /// </summary>
        public const int ServerError = 500;
        public const string ServerErrorReason = "Server Error";

        /// <summary>
        /// Gets the default reason phrase for a given error code.
        /// </summary>
        public static string GetReasonPhrase(int errorCode)
        {
            return errorCode switch
            {
                TryAlternate => TryAlternateReason,
                BadRequest => BadRequestReason,
                Unauthorized => UnauthorizedReason,
                UnknownAttribute => UnknownAttributeReason,
                StaleNonce => StaleNonceReason,
                ServerError => ServerErrorReason,
                _ => "Unknown Error"
            };
        }

        /// <summary>
        /// Creates an ErrorCodeAttribute for the given error code with default reason phrase.
        /// </summary>
        public static ErrorCodeAttribute CreateErrorAttribute(int errorCode)
        {
            return new ErrorCodeAttribute(errorCode, GetReasonPhrase(errorCode));
        }

        /// <summary>
        /// Creates an ErrorCodeAttribute for the given error code with custom reason phrase.
        /// </summary>
        public static ErrorCodeAttribute CreateErrorAttribute(int errorCode, string reasonPhrase)
        {
            return new ErrorCodeAttribute(errorCode, reasonPhrase);
        }
    }
}
