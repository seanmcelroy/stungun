# Stungun Enhancement Roadmap

This document outlines detailed recommendations for enhancing the STUN/TURN implementation. Each section includes background context, specific implementation tasks, affected files, and references to relevant RFCs.

---

## Table of Contents

1. [Complete STUN Authentication (RFC 5389)](#1-complete-stun-authentication-rfc-5389)
2. [TCP Server Implementation](#2-tcp-server-implementation)
3. [Error Response Handling](#3-error-response-handling)
4. [RFC 5780 NAT Behavior Discovery](#4-rfc-5780-nat-behavior-discovery)
5. [TURN Support (RFC 5766)](#5-turn-support-rfc-5766)
6. [TLS/DTLS Transport](#6-tlsdtls-transport)
7. [ICE Support (RFC 8445)](#7-ice-support-rfc-8445)
8. [Test Coverage](#8-test-coverage)
9. [Configuration & Observability](#9-configuration--observability)
10. [IPv6 Improvements](#10-ipv6-improvements)
11. [Alternate Server Support](#11-alternate-server-support)

---

## 1. Complete STUN Authentication (RFC 5389)

### Background

RFC 5389 Section 10 defines two credential mechanisms for STUN authentication:
- **Short-term credentials**: Username/password valid for a single session (used in ICE)
- **Long-term credentials**: Username/password with realm/nonce (used in TURN)

The current implementation defines `MessageIntegrity`, `Fingerprint`, `Username`, `Realm`, and `Nonce` in `AttributeType.cs` but does not implement the actual cryptographic operations.

### Implementation Tasks

#### 1.1 MESSAGE-INTEGRITY Attribute (HMAC-SHA1)

Create `MessageIntegrityAttribute.cs`:

```
Location: common/core/MessageIntegrityAttribute.cs
```

- Compute HMAC-SHA1 over the STUN message up to (but excluding) the MESSAGE-INTEGRITY attribute
- The message length in the header must be adjusted to point to the end of MESSAGE-INTEGRITY
- Key derivation:
  - Short-term: `key = SASLprep(password)`
  - Long-term: `key = MD5(username:realm:SASLprep(password))`
- Output is 20 bytes (HMAC-SHA1 output length)

```csharp
public class MessageIntegrityAttribute : MessageAttribute
{
    public byte[] HmacValue { get; set; } // 20 bytes

    public static byte[] ComputeShortTermKey(string password);
    public static byte[] ComputeLongTermKey(string username, string realm, string password);
    public static byte[] ComputeHmac(byte[] messageBytes, byte[] key);
    public bool Validate(byte[] messageBytes, byte[] key);
}
```

#### 1.2 FINGERPRINT Attribute (CRC-32)

Create `FingerprintAttribute.cs`:

```
Location: common/core/FingerprintAttribute.cs
```

- Compute CRC-32 over the STUN message up to (but excluding) the FINGERPRINT attribute
- XOR the result with `0x5354554E` ("STUN" in ASCII)
- Always appears as the last attribute if present
- Output is 4 bytes

```csharp
public class FingerprintAttribute : MessageAttribute
{
    public uint Crc32Value { get; set; }

    public static uint Compute(byte[] messageBytes);
    public bool Validate(byte[] messageBytes);
}
```

#### 1.3 Username, Realm, Nonce Attributes

Create string-based attribute classes:

```
Locations:
- common/core/UsernameAttribute.cs
- common/core/RealmAttribute.cs
- common/core/NonceAttribute.cs
```

These are simple UTF-8 string attributes with the following considerations:
- Username: Max 513 bytes, must be valid UTF-8
- Realm: Max 127 characters, quoted string
- Nonce: Max 127 characters, sequence of qdtext or quoted-pair

#### 1.4 Modify Message Serialization

Update `Message.cs` and `MessageUtility.cs`:

- Add `ToByteArrayForIntegrity()` method that serializes with adjusted length for HMAC calculation
- Add `AppendIntegrityAndFingerprint(byte[] key)` method for outgoing messages
- Add `ValidateIntegrity(byte[] key)` and `ValidateFingerprint()` methods for incoming messages

#### 1.5 Server-Side Authentication Flow

Update `StunUdpServer.cs`:

- Add credential storage/lookup mechanism (interface `ICredentialProvider`)
- Implement 401 Unauthorized response with REALM and NONCE
- Validate MESSAGE-INTEGRITY on authenticated requests
- Support nonce expiration and stale nonce handling (438 Stale Nonce error)

### Affected Files

| File | Changes |
|------|---------|
| `common/core/AttributeType.cs` | Already has definitions |
| `common/core/MessageIntegrityAttribute.cs` | New file |
| `common/core/FingerprintAttribute.cs` | New file |
| `common/core/UsernameAttribute.cs` | New file |
| `common/core/RealmAttribute.cs` | New file |
| `common/core/NonceAttribute.cs` | New file |
| `common/core/Message.cs` | Add integrity/fingerprint methods |
| `common/core/MessageAttribute.cs` | Add parsing for new attribute types |
| `common/server/StunUdpServer.cs` | Add authentication flow |
| `common/server/ICredentialProvider.cs` | New interface |

### References

- RFC 5389 Section 10: Authentication and Message-Integrity Mechanisms
- RFC 5389 Section 15.4: MESSAGE-INTEGRITY
- RFC 5389 Section 15.5: FINGERPRINT

---

## 2. TCP Server Implementation

### Background

The current implementation has `StunTcpClient` but no corresponding TCP server. RFC 5389 Section 7.2.2 specifies TCP framing requirements where each STUN message is preceded by a 2-byte length field.

### Implementation Tasks

#### 2.1 Create StunTcpServer

```
Location: common/server/StunTcpServer.cs
```

```csharp
public class StunTcpServer : IDisposable
{
    private TcpListener? _listener;
    private readonly ConcurrentDictionary<string, TcpClient> _connections;

    public void Start(int port, CancellationToken ct);
    public void Stop();

    private async Task AcceptConnectionsAsync(CancellationToken ct);
    private async Task HandleConnectionAsync(TcpClient client, CancellationToken ct);
    private async Task<Message?> ReadFramedMessageAsync(NetworkStream stream, CancellationToken ct);
    private async Task WriteFramedMessageAsync(NetworkStream stream, Message message, CancellationToken ct);
}
```

#### 2.2 Implement TCP Framing

Per RFC 5389 Section 7.2.2:
- Each message is preceded by 2 bytes indicating the message length
- Length does NOT include the 2-byte length field itself
- Length is in network byte order (big-endian)

```csharp
// Reading
var lengthBytes = new byte[2];
await stream.ReadAsync(lengthBytes, 0, 2);
var messageLength = (ushort)((lengthBytes[0] << 8) | lengthBytes[1]);
var messageBytes = new byte[messageLength];
await stream.ReadAsync(messageBytes, 0, messageLength);

// Writing
var messageBytes = message.ToByteArray();
var lengthBytes = new byte[] { (byte)(messageBytes.Length >> 8), (byte)(messageBytes.Length & 0xFF) };
await stream.WriteAsync(lengthBytes, 0, 2);
await stream.WriteAsync(messageBytes, 0, messageBytes.Length);
```

#### 2.3 Connection Management

- Track active connections with unique identifiers
- Implement connection timeout (RFC recommends 10 minutes idle timeout)
- Handle graceful disconnection
- Support concurrent connections

#### 2.4 Update StunTcpClient Framing

The current `StunTcpClient.cs` reads messages directly without the 2-byte length prefix. Update to:
- Send the 2-byte length prefix before each message
- Read the 2-byte length prefix when receiving responses

**Current code at line 70:**
```csharp
await ns.WriteAsync(messageBytes, 0, messageBytes.Length, cancellationToken);
```

**Should become:**
```csharp
var lengthPrefix = new byte[] { (byte)(messageBytes.Length >> 8), (byte)(messageBytes.Length & 0xFF) };
await ns.WriteAsync(lengthPrefix, 0, 2, cancellationToken);
await ns.WriteAsync(messageBytes, 0, messageBytes.Length, cancellationToken);
```

### Affected Files

| File | Changes |
|------|---------|
| `common/server/StunTcpServer.cs` | New file |
| `common/client/StunTcpClient.cs` | Add TCP framing |
| `server/Program.cs` | Add TCP server startup option |

### References

- RFC 5389 Section 7.2.2: Sending over TCP or TLS-over-TCP

---

## 3. Error Response Handling

### Background

The current server only handles successful binding requests. RFC 5389 defines several error codes that should be returned in error responses. The `BindingError` message type (0x0111) exists but is not generated.

### Implementation Tasks

#### 3.1 Create ErrorCodeAttribute

```
Location: common/core/ErrorCodeAttribute.cs
```

```csharp
public class ErrorCodeAttribute : MessageAttribute
{
    public ushort ErrorClass { get; set; }    // 3 bits (values 3-6)
    public byte ErrorNumber { get; set; }      // 8 bits (0-99)
    public string ReasonPhrase { get; set; }   // UTF-8, max 127 chars

    public int ErrorCode => (ErrorClass * 100) + ErrorNumber;

    // Wire format: 2 reserved bytes, 1 byte (class in bits 0-2), 1 byte (number), then reason phrase
}
```

#### 3.2 Define Standard Error Codes

```csharp
public static class StunErrorCodes
{
    public const int TryAlternate = 300;      // Client should use alternate server
    public const int BadRequest = 400;         // Malformed request
    public const int Unauthorized = 401;       // Missing/invalid credentials
    public const int UnknownAttribute = 420;   // Unknown comprehension-required attribute
    public const int StaleNonce = 438;         // Nonce expired, retry with new nonce
    public const int ServerError = 500;        // Server internal error
}
```

#### 3.3 Create UnknownAttributesAttribute

```
Location: common/core/UnknownAttributesAttribute.cs
```

When a comprehension-required attribute is not understood, include this attribute listing the unknown attribute types:

```csharp
public class UnknownAttributesAttribute : MessageAttribute
{
    public List<ushort> UnknownTypes { get; set; }
    // Wire format: List of 16-bit attribute types, padded to 4-byte boundary
}
```

#### 3.4 Add Error Response Generation to Server

Update `StunUdpServer.cs` ProcessingLoop:

```csharp
private static Message CreateErrorResponse(Message request, int errorCode, string reason)
{
    var errorAttr = new ErrorCodeAttribute
    {
        ErrorClass = (ushort)(errorCode / 100),
        ErrorNumber = (byte)(errorCode % 100),
        ReasonPhrase = reason
    };

    return new Message
    {
        Header = new MessageHeader
        {
            Type = MessageType.BindingError,
            MagicCookie = request.Header.MagicCookie,
            TransactionId = request.Header.TransactionId,
            // ... calculate length
        },
        Attributes = new List<MessageAttribute> { errorAttr }
    };
}
```

#### 3.5 Update Message Parsing for Comprehension-Required Attributes

Current behavior in `MessageAttribute.cs` line 51 throws for unknown comprehension-required attributes. Instead:
- Collect unknown comprehension-required attribute types
- Return them to the caller so an error response can be generated
- Only throw if we're a client receiving an unexpected attribute

### Affected Files

| File | Changes |
|------|---------|
| `common/core/ErrorCodeAttribute.cs` | New file |
| `common/core/UnknownAttributesAttribute.cs` | New file |
| `common/core/StunErrorCodes.cs` | New file |
| `common/core/MessageAttribute.cs` | Improve unknown attribute handling |
| `common/server/StunUdpServer.cs` | Add error response generation |

### References

- RFC 5389 Section 15.6: ERROR-CODE
- RFC 5389 Section 15.9: UNKNOWN-ATTRIBUTES

---

## 4. RFC 5780 NAT Behavior Discovery

### Background

RFC 5780 supersedes RFC 3489 for NAT behavior discovery. It separately characterizes:
- **Mapping behavior**: How the NAT assigns external addresses (Endpoint-Independent, Address-Dependent, Address-and-Port-Dependent)
- **Filtering behavior**: What packets the NAT allows through (Endpoint-Independent, Address-Dependent, Address-and-Port-Dependent)

The current `DiscoveryClient.cs` has a stubbed `DiscoverUdpRfc5780Async()` method that returns Unknown.

### Implementation Tasks

#### 4.1 Implement Mapping Behavior Detection

The algorithm requires communicating with the same server from different local endpoints:

```csharp
public async Task<NatMappingTypeRfc5780> DetectMappingBehaviorAsync()
{
    // Test 1: Send binding request to primary address
    // Get XOR-MAPPED-ADDRESS and OTHER-ADDRESS from response

    // Test 2: Send binding request to alternate address (from OTHER-ADDRESS)
    // Compare XOR-MAPPED-ADDRESS

    // If same external IP:port -> Endpoint-Independent Mapping
    // If same external IP, different port -> Address-Dependent Mapping
    // If different external IP:port -> Address-and-Port-Dependent Mapping
}
```

#### 4.2 Implement Filtering Behavior Detection

Uses CHANGE-REQUEST attribute with RESPONSE-ORIGIN:

```csharp
public async Task<NatFilteringTypeRfc5780> DetectFilteringBehaviorAsync()
{
    // Test 1: Request response from alternate IP and port
    // If received -> Endpoint-Independent Filtering

    // Test 2: Request response from same IP, alternate port
    // If received -> Address-Dependent Filtering
    // If not received -> Address-and-Port-Dependent Filtering
}
```

#### 4.3 Update ChangeRequestAttribute

The current `ChangeRequestAttribute.cs` may need updates for RFC 5780 compliance. Verify the wire format matches:
- Bit 0x04: Change IP
- Bit 0x02: Change Port

#### 4.4 Handle RESPONSE-ORIGIN and OTHER-ADDRESS

These attributes are already defined in `AttributeType.cs` and parsed as `AddressAttribute`. Ensure the server includes them when the client can support RFC 5780 tests.

#### 4.5 Complete the DiscoverUdpRfc5780Async Implementation

```csharp
public async Task<(NatMappingTypeRfc5780 mapping, NatFilteringTypeRfc5780 filtering)> DiscoverUdpRfc5780Async(
    CancellationToken cancellationToken = default)
{
    var mapping = await DetectMappingBehaviorAsync(cancellationToken);
    var filtering = await DetectFilteringBehaviorAsync(cancellationToken);
    return (mapping, filtering);
}
```

### Affected Files

| File | Changes |
|------|---------|
| `common/client/DiscoveryClient.cs` | Complete RFC 5780 implementation |
| `common/client/NatMappingTypeRfc5780.cs` | Already exists, verify enum values |
| `common/client/NatFilteringTypeRfc5780.cs` | Already exists, verify enum values |
| `common/core/ChangeRequestAttribute.cs` | Verify wire format |
| `common/server/StunUdpServer.cs` | Add RESPONSE-ORIGIN, OTHER-ADDRESS to responses |

### References

- RFC 5780: NAT Behavior Discovery Using Session Traversal Utilities for NAT (STUN)

---

## 5. TURN Support (RFC 5766)

### Background

TURN (Traversal Using Relays around NAT) extends STUN to provide relay functionality when direct peer-to-peer communication fails. This is a significant feature addition requiring new message types, attributes, and server-side state management.

### Implementation Tasks

#### 5.1 Add TURN Message Types

Update `MessageType.cs`:

```csharp
public enum MessageType : ushort
{
    // Existing STUN types...

    // TURN Request/Response/Error
    Allocate = 0x0003,
    AllocateResponse = 0x0103,
    AllocateError = 0x0113,

    Refresh = 0x0004,
    RefreshResponse = 0x0104,
    RefreshError = 0x0114,

    Send = 0x0006,          // Indication (no response)
    Data = 0x0007,          // Indication (no response)

    CreatePermission = 0x0008,
    CreatePermissionResponse = 0x0108,
    CreatePermissionError = 0x0118,

    ChannelBind = 0x0009,
    ChannelBindResponse = 0x0109,
    ChannelBindError = 0x0119,
}
```

#### 5.2 Add TURN Attributes

New attribute types for `AttributeType.cs`:

```csharp
// TURN-specific attributes
ChannelNumber = 0x000C,
Lifetime = 0x000D,
XorPeerAddress = 0x0012,
Data = 0x0013,
XorRelayedAddress = 0x0016,
RequestedAddressFamily = 0x0017,
EvenPort = 0x0018,
RequestedTransport = 0x0019,
DontFragment = 0x001A,
ReservationToken = 0x0022,
```

Create corresponding attribute classes:

```
common/core/turn/LifetimeAttribute.cs
common/core/turn/XorPeerAddressAttribute.cs
common/core/turn/XorRelayedAddressAttribute.cs
common/core/turn/ChannelNumberAttribute.cs
common/core/turn/RequestedTransportAttribute.cs
common/core/turn/DataAttribute.cs
common/core/turn/EvenPortAttribute.cs
common/core/turn/ReservationTokenAttribute.cs
```

#### 5.3 Create TURN Server

```
Location: common/server/TurnServer.cs
```

The TURN server needs to manage:

```csharp
public class TurnServer : IDisposable
{
    // Allocation management
    private readonly ConcurrentDictionary<AllocationKey, Allocation> _allocations;

    // Permission management (5-tuple -> permission)
    private readonly ConcurrentDictionary<string, Permission> _permissions;

    // Channel bindings
    private readonly ConcurrentDictionary<ushort, ChannelBinding> _channels;

    public async Task HandleAllocateAsync(Message request, IPEndPoint clientEndpoint);
    public async Task HandleRefreshAsync(Message request, IPEndPoint clientEndpoint);
    public async Task HandleCreatePermissionAsync(Message request, IPEndPoint clientEndpoint);
    public async Task HandleChannelBindAsync(Message request, IPEndPoint clientEndpoint);
    public async Task HandleSendIndicationAsync(Message indication, IPEndPoint clientEndpoint);

    // Relay data from peer back to client
    private async Task RelayDataToPeerAsync(Allocation allocation, byte[] data, IPEndPoint peerEndpoint);
    private async Task RelayDataToClientAsync(Allocation allocation, byte[] data, IPEndPoint peerEndpoint);
}

public class Allocation
{
    public IPEndPoint ClientEndpoint { get; set; }
    public IPEndPoint RelayedEndpoint { get; set; }
    public byte[] TransactionId { get; set; }
    public DateTime Expiration { get; set; }
    public TransportProtocol Protocol { get; set; }
    public List<Permission> Permissions { get; set; }
    public Dictionary<ushort, ChannelBinding> Channels { get; set; }
}
```

#### 5.4 Create TURN Client

```
Location: common/client/TurnClient.cs
```

```csharp
public class TurnClient : IDisposable
{
    public Task<AllocationResult> AllocateAsync(string username, string password);
    public Task<bool> RefreshAsync(int lifetime = 600);
    public Task<bool> CreatePermissionAsync(IPAddress peerAddress);
    public Task<bool> ChannelBindAsync(ushort channelNumber, IPEndPoint peerEndpoint);
    public Task SendAsync(byte[] data, IPEndPoint peerEndpoint);
    public event EventHandler<DataReceivedEventArgs> DataReceived;
}
```

#### 5.5 Implement Allocation Lifecycle

- Default lifetime: 600 seconds (10 minutes)
- Maximum lifetime: 3600 seconds (1 hour)
- Client must refresh before expiration
- Server garbage collects expired allocations

#### 5.6 Implement Channel Data Messages

For efficiency, TURN supports channel data messages that bypass STUN framing:

```
+-------------------------------+
|         Channel Number        |  2 bytes
+-------------------------------+
|            Length             |  2 bytes
+-------------------------------+
|                               |
|        Application Data       |
|                               |
+-------------------------------+
```

Channel numbers are in range 0x4000-0x7FFE.

### Affected Files

| File | Changes |
|------|---------|
| `common/core/MessageType.cs` | Add TURN message types |
| `common/core/AttributeType.cs` | Add TURN attributes |
| `common/core/turn/*.cs` | New directory with TURN attributes |
| `common/server/TurnServer.cs` | New file |
| `common/server/Allocation.cs` | New file |
| `common/server/Permission.cs` | New file |
| `common/server/ChannelBinding.cs` | New file |
| `common/client/TurnClient.cs` | New file |

### References

- RFC 5766: Traversal Using Relays around NAT (TURN)
- RFC 6062: TURN Extensions for TCP Allocations

---

## 6. TLS/DTLS Transport

### Background

Secure transport is essential for production deployments:
- **TLS**: Secure TCP transport (STUN over TLS, port 5349)
- **DTLS**: Secure UDP transport (STUN over DTLS, port 5349)

WebRTC mandates DTLS for data channels and media.

### Implementation Tasks

#### 6.1 Create StunTlsClient

```
Location: common/client/StunTlsClient.cs
```

```csharp
public class StunTlsClient : IStunClient, IDisposable
{
    private SslStream? _sslStream;
    private TcpClient? _tcpClient;

    public X509Certificate2? ClientCertificate { get; set; }
    public bool ValidateServerCertificate { get; set; } = true;

    public async Task<MessageResponse> BindingRequestAsync(...);

    private async Task ConnectAsync(string hostname, int port, CancellationToken ct);
}
```

Use `System.Net.Security.SslStream`:

```csharp
_tcpClient = new TcpClient();
await _tcpClient.ConnectAsync(hostname, port);

_sslStream = new SslStream(
    _tcpClient.GetStream(),
    false,
    ValidateServerCertificate ? null : (sender, cert, chain, errors) => true
);

await _sslStream.AuthenticateAsClientAsync(hostname);
```

#### 6.2 Create StunTlsServer

```
Location: common/server/StunTlsServer.cs
```

```csharp
public class StunTlsServer : IDisposable
{
    public X509Certificate2 ServerCertificate { get; set; }

    private async Task HandleTlsConnectionAsync(TcpClient client, CancellationToken ct)
    {
        using var sslStream = new SslStream(client.GetStream(), false);
        await sslStream.AuthenticateAsServerAsync(ServerCertificate);

        // Process STUN messages over SSL stream
    }
}
```

#### 6.3 Create StunDtlsClient

```
Location: common/client/StunDtlsClient.cs
```

.NET doesn't have built-in DTLS support. Options:
1. Use `System.Net.Quic` (requires .NET 7+, Windows/Linux)
2. Use a third-party library like `Waher.Security.DTLS`
3. Use native interop with OpenSSL

Recommend option 2 or waiting for better .NET DTLS support:

```csharp
public class StunDtlsClient : IStunClient, IDisposable
{
    // Using Waher.Security.DTLS or similar
    private DtlsEndpoint? _dtlsEndpoint;

    public async Task<MessageResponse> BindingRequestAsync(...);
}
```

#### 6.4 Create StunDtlsServer

```
Location: common/server/StunDtlsServer.cs
```

Similar considerations as the client - requires third-party DTLS library.

#### 6.5 Certificate Management

Create utility class for certificate handling:

```
Location: common/security/CertificateManager.cs
```

```csharp
public static class CertificateManager
{
    public static X509Certificate2 LoadFromFile(string path, string password);
    public static X509Certificate2 GenerateSelfSigned(string subjectName, int validDays = 365);
    public static byte[] GetFingerprint(X509Certificate2 cert, HashAlgorithmName algorithm);
}
```

### Affected Files

| File | Changes |
|------|---------|
| `common/client/StunTlsClient.cs` | New file |
| `common/client/StunDtlsClient.cs` | New file |
| `common/server/StunTlsServer.cs` | New file |
| `common/server/StunDtlsServer.cs` | New file |
| `common/security/CertificateManager.cs` | New file |
| `common/common.csproj` | Add DTLS package reference |

### References

- RFC 5389 Section 7.2.2: Sending over TCP or TLS-over-TCP
- RFC 6347: Datagram Transport Layer Security Version 1.2

---

## 7. ICE Support (RFC 8445)

### Background

ICE (Interactive Connectivity Establishment) is the framework used by WebRTC to find the best path between peers. It uses STUN for connectivity checks and TURN for relay fallback.

### Implementation Tasks

#### 7.1 Add ICE Attributes

Update `AttributeType.cs`:

```csharp
// ICE attributes
Priority = 0x0024,
UseCandidate = 0x0025,
IceControlled = 0x8029,
IceControlling = 0x802A,
```

Create attribute classes:

```
common/core/ice/PriorityAttribute.cs
common/core/ice/UseCandidateAttribute.cs
common/core/ice/IceControlledAttribute.cs
common/core/ice/IceControllingAttribute.cs
```

#### 7.2 PriorityAttribute

```csharp
public class PriorityAttribute : MessageAttribute
{
    public uint Priority { get; set; }

    // Priority calculation per RFC 8445 Section 5.1.2
    public static uint Calculate(CandidateType type, int localPreference, int componentId)
    {
        int typePreference = type switch
        {
            CandidateType.Host => 126,
            CandidateType.PeerReflexive => 110,
            CandidateType.ServerReflexive => 100,
            CandidateType.Relayed => 0,
            _ => 0
        };

        return (uint)((typePreference << 24) + (localPreference << 8) + (256 - componentId));
    }
}
```

#### 7.3 ICE Controlling/Controlled

```csharp
public class IceControllingAttribute : MessageAttribute
{
    public ulong TieBreaker { get; set; }  // 64-bit random number
}

public class IceControlledAttribute : MessageAttribute
{
    public ulong TieBreaker { get; set; }  // 64-bit random number
}
```

#### 7.4 ICE Agent Implementation

```
Location: common/ice/IceAgent.cs
```

```csharp
public class IceAgent : IDisposable
{
    public IceRole Role { get; set; }  // Controlling or Controlled
    public List<IceCandidate> LocalCandidates { get; }
    public List<IceCandidate> RemoteCandidates { get; set; }
    public List<CandidatePair> CheckList { get; }

    public event EventHandler<IceCandidate> OnLocalCandidate;
    public event EventHandler<CandidatePair> OnNominatedPair;
    public event EventHandler<IceConnectionState> OnStateChange;

    public async Task GatherCandidatesAsync(IEnumerable<string> stunServers, IEnumerable<string> turnServers);
    public async Task StartConnectivityChecksAsync();
    public void AddRemoteCandidate(IceCandidate candidate);

    private async Task PerformConnectivityCheckAsync(CandidatePair pair);
    private void HandleTriggeredCheck(CandidatePair pair);
    private void HandleRoleConflict(CandidatePair pair);
}

public enum IceConnectionState
{
    New,
    Gathering,
    Checking,
    Connected,
    Completed,
    Failed,
    Disconnected,
    Closed
}
```

#### 7.5 Candidate Representation

```
Location: common/ice/IceCandidate.cs
```

```csharp
public class IceCandidate
{
    public string Foundation { get; set; }
    public int ComponentId { get; set; }
    public TransportProtocol Transport { get; set; }
    public uint Priority { get; set; }
    public IPEndPoint Endpoint { get; set; }
    public CandidateType Type { get; set; }
    public IPEndPoint? RelatedEndpoint { get; set; }  // For srflx/relay

    // SDP format: "candidate:foundation component transport priority address port typ type"
    public string ToSdpString();
    public static IceCandidate ParseSdp(string sdp);
}

public enum CandidateType
{
    Host,
    ServerReflexive,
    PeerReflexive,
    Relayed
}
```

### Affected Files

| File | Changes |
|------|---------|
| `common/core/AttributeType.cs` | Add ICE attributes |
| `common/core/ice/PriorityAttribute.cs` | New file |
| `common/core/ice/UseCandidateAttribute.cs` | New file |
| `common/core/ice/IceControllingAttribute.cs` | New file |
| `common/core/ice/IceControlledAttribute.cs` | New file |
| `common/ice/IceAgent.cs` | New file |
| `common/ice/IceCandidate.cs` | New file |
| `common/ice/CandidatePair.cs` | New file |
| `common/ice/IceConnectionState.cs` | New file |

### References

- RFC 8445: Interactive Connectivity Establishment (ICE)
- RFC 8838: Trickle ICE

---

## 8. Test Coverage

### Background

Current test coverage is minimal with only 2 tests in `MessageTest.cs`. Comprehensive testing is essential for protocol correctness and regression prevention.

### Implementation Tasks

#### 8.1 Unit Tests for Attributes

```
Location: common.tests/AttributeTests.cs
```

Test each attribute type:
- Serialization/deserialization round-trip
- Edge cases (max values, empty values)
- Invalid input handling

```csharp
public class AttributeTests
{
    [Fact]
    public void XorMappedAddress_IPv4_RoundTrip() { }

    [Fact]
    public void XorMappedAddress_IPv6_RoundTrip() { }

    [Fact]
    public void ChangeRequest_AllCombinations() { }

    [Theory]
    [InlineData("192.168.1.1", 12345)]
    [InlineData("0.0.0.0", 0)]
    [InlineData("255.255.255.255", 65535)]
    public void MappedAddress_VariousAddresses(string ip, int port) { }
}
```

#### 8.2 Unit Tests for Message Parsing

```
Location: common.tests/MessageParsingTests.cs
```

```csharp
public class MessageParsingTests
{
    [Fact]
    public void Parse_ValidBindingRequest_Success() { }

    [Fact]
    public void Parse_TooShort_ThrowsArgumentOutOfRangeException() { }

    [Fact]
    public void Parse_InvalidMagicCookie_Behavior() { }

    [Fact]
    public void Parse_UnknownComprehensionRequired_Throws() { }

    [Fact]
    public void Parse_UnknownComprehensionOptional_Skips() { }

    [Fact]
    public void Parse_MultipleAttributes_AllParsed() { }
}
```

#### 8.3 Unit Tests for Authentication

```
Location: common.tests/AuthenticationTests.cs
```

```csharp
public class AuthenticationTests
{
    [Fact]
    public void MessageIntegrity_ShortTerm_Compute() { }

    [Fact]
    public void MessageIntegrity_LongTerm_Compute() { }

    [Fact]
    public void MessageIntegrity_Validate_ValidMessage() { }

    [Fact]
    public void MessageIntegrity_Validate_TamperedMessage() { }

    [Fact]
    public void Fingerprint_Compute_CorrectValue() { }

    [Fact]
    public void Fingerprint_Validate_ValidMessage() { }
}
```

#### 8.4 Integration Tests

```
Location: common.tests/IntegrationTests.cs
```

```csharp
public class IntegrationTests
{
    [Fact]
    public async Task UdpClient_LocalServer_BindingRequest()
    {
        using var server = new StunUdpServer(...);
        server.Start(3478);

        using var client = new StunUdpClient("127.0.0.1", 3478);
        var response = await client.BindingRequestAsync();

        Assert.True(response.Success);
        Assert.NotNull(response.Message.Attributes);
    }

    [Fact]
    public async Task TcpClient_LocalServer_BindingRequest() { }

    [Fact]
    public async Task DiscoveryClient_LocalServer_NatType() { }
}
```

#### 8.5 Interoperability Tests

```
Location: common.tests/InteropTests.cs
```

Test against public STUN servers to verify interoperability:

```csharp
public class InteropTests
{
    private static readonly string[] PublicStunServers = new[]
    {
        "stun.l.google.com:19302",
        "stun.stunprotocol.org:3478"
    };

    [Theory]
    [MemberData(nameof(PublicStunServers))]
    public async Task BindingRequest_PublicServer_ReturnsXorMappedAddress(string server) { }
}
```

#### 8.6 Property-Based Tests

Consider using FsCheck or similar for property-based testing:

```csharp
[Property]
public Property MessageRoundTrip_PreservesData(byte[] transactionId, ushort port)
{
    // Generate random valid message, serialize, parse, compare
}
```

### Affected Files

| File | Changes |
|------|---------|
| `common.tests/AttributeTests.cs` | New file |
| `common.tests/MessageParsingTests.cs` | New file |
| `common.tests/AuthenticationTests.cs` | New file |
| `common.tests/IntegrationTests.cs` | New file |
| `common.tests/InteropTests.cs` | New file |
| `common.tests/common.tests.csproj` | Add test packages |

---

## 9. Configuration & Observability

### Background

The current implementation has hardcoded values and writes debug output to stderr. Production deployments require proper configuration and monitoring.

### Implementation Tasks

#### 9.1 Configuration Model

```
Location: common/config/StunServerConfiguration.cs
```

```csharp
public class StunServerConfiguration
{
    public int UdpPort { get; set; } = 3478;
    public int TcpPort { get; set; } = 3478;
    public int TlsPort { get; set; } = 5349;

    public int ReceiveTimeoutMs { get; set; } = 5000;
    public int MaxConcurrentConnections { get; set; } = 1000;
    public int TransactionLogSize { get; set; } = 100;

    public bool EnableAuthentication { get; set; } = false;
    public string? Realm { get; set; }
    public int NonceLifetimeSeconds { get; set; } = 3600;

    public IPAddress[]? AlternateAddresses { get; set; }
    public int[]? AlternatePorts { get; set; }

    public LogLevel MinimumLogLevel { get; set; } = LogLevel.Information;
}
```

#### 9.2 Structured Logging

Replace `Console.Error.WriteLine` calls with proper logging:

```
Location: common/logging/IStunLogger.cs
```

```csharp
public interface IStunLogger
{
    void LogDebug(string message, params object[] args);
    void LogInformation(string message, params object[] args);
    void LogWarning(string message, params object[] args);
    void LogError(Exception ex, string message, params object[] args);
}

// Default implementation using Microsoft.Extensions.Logging
public class StunLogger : IStunLogger
{
    private readonly ILogger _logger;
    // ...
}
```

Update `StunUdpServer.cs` line 134, 136, 152 etc:

```csharp
// Before:
await Console.Error.WriteLineAsync($"Attribute count: {attributeList.Count}");

// After:
_logger.LogDebug("Sending response with {AttributeCount} attributes", attributeList.Count);
```

#### 9.3 Metrics Collection

```
Location: common/metrics/StunMetrics.cs
```

```csharp
public class StunMetrics
{
    public long TotalRequestsReceived { get; private set; }
    public long TotalResponsesSent { get; private set; }
    public long TotalErrors { get; private set; }
    public long ActiveConnections { get; private set; }

    public ConcurrentDictionary<MessageType, long> RequestsByType { get; }
    public ConcurrentDictionary<int, long> ErrorsByCode { get; }

    public TimeSpan AverageResponseTime { get; }
    public TimeSpan MaxResponseTime { get; }

    public void RecordRequest(MessageType type);
    public void RecordResponse(TimeSpan duration);
    public void RecordError(int errorCode);

    // For Prometheus/OpenTelemetry export
    public IDictionary<string, object> GetMetrics();
}
```

#### 9.4 Health Checks

```
Location: common/health/StunHealthCheck.cs
```

```csharp
public class StunHealthCheck
{
    public bool IsHealthy { get; }
    public DateTime LastRequestTime { get; }
    public int PendingRequests { get; }
    public long UptimeSeconds { get; }

    public HealthCheckResult Check();
}
```

#### 9.5 Configuration Loading

Support JSON configuration files:

```json
{
  "stun": {
    "udpPort": 3478,
    "tcpPort": 3478,
    "authentication": {
      "enabled": true,
      "realm": "example.com"
    },
    "logging": {
      "level": "Information"
    }
  }
}
```

### Affected Files

| File | Changes |
|------|---------|
| `common/config/StunServerConfiguration.cs` | New file |
| `common/config/StunClientConfiguration.cs` | New file |
| `common/logging/IStunLogger.cs` | New file |
| `common/logging/StunLogger.cs` | New file |
| `common/metrics/StunMetrics.cs` | New file |
| `common/health/StunHealthCheck.cs` | New file |
| `common/server/StunUdpServer.cs` | Inject logger, metrics |
| `common/client/StunUdpClient.cs` | Inject logger |
| `server/Program.cs` | Load configuration |
| `server/appsettings.json` | New file |

---

## 10. IPv6 Improvements

### Background

The current implementation has IPv6 support in `XorMappedAddressAttribute.cs` but limited testing and no dual-stack configuration options.

### Implementation Tasks

#### 10.1 Dual-Stack Server Binding

Update `StunUdpServer.cs`:

```csharp
public void Start(ushort port, bool dualStack = true, CancellationToken ct = default)
{
    if (dualStack && Socket.OSSupportsIPv6)
    {
        // Bind to IPv6 with dual-stack (handles IPv4 too on most platforms)
        var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
        socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
        socket.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
        UdpServer = new UdpClient();
        UdpServer.Client = socket;
    }
    else
    {
        UdpServer = new UdpClient(port);
    }
}
```

#### 10.2 IPv6 Address Handling in Attributes

Verify `XorMappedAddressAttribute.cs` correctly handles:
- IPv4-mapped IPv6 addresses (::ffff:192.0.2.1)
- Link-local addresses (fe80::)
- Zone IDs for link-local

#### 10.3 IPv6 Preference Configuration

```csharp
public enum AddressFamilyPreference
{
    IPv4Only,
    IPv6Only,
    PreferIPv4,
    PreferIPv6,
    DualStack
}
```

#### 10.4 Client IPv6 Support

Update `StunUdpClient.cs` and `StunTcpClient.cs`:

```csharp
public StunUdpClient(string hostname, int port = 3478, AddressFamilyPreference preference = AddressFamilyPreference.DualStack)
{
    // Resolve hostname and select address based on preference
    var addresses = await Dns.GetHostAddressesAsync(hostname);
    var selectedAddress = SelectAddress(addresses, preference);
    // ...
}
```

#### 10.5 IPv6 Unit Tests

```csharp
[Fact]
public void XorMappedAddress_IPv6_GlobalUnicast()
{
    var addr = IPAddress.Parse("2001:db8::1");
    // Test serialization/deserialization
}

[Fact]
public void XorMappedAddress_IPv6_LinkLocal()
{
    var addr = IPAddress.Parse("fe80::1");
    // Test with and without zone ID
}

[Fact]
public void XorMappedAddress_IPv4MappedIPv6()
{
    var addr = IPAddress.Parse("::ffff:192.0.2.1");
    // Verify correct handling
}
```

### Affected Files

| File | Changes |
|------|---------|
| `common/server/StunUdpServer.cs` | Dual-stack support |
| `common/server/StunTcpServer.cs` | Dual-stack support |
| `common/client/StunUdpClient.cs` | IPv6 preference |
| `common/client/StunTcpClient.cs` | IPv6 preference |
| `common/core/XorMappedAddressAttribute.cs` | Verify IPv6 handling |
| `common/config/AddressFamilyPreference.cs` | New file |
| `common.tests/IPv6Tests.cs` | New file |

---

## 11. Alternate Server Support

### Background

RFC 5389 defines the ALTERNATE-SERVER attribute for redirecting clients to different servers. This enables load balancing, geographic distribution, and graceful failover.

### Implementation Tasks

#### 11.1 AlternateServerAttribute

The attribute type already exists. Create the implementation:

```
Location: common/core/AlternateServerAttribute.cs
```

```csharp
public class AlternateServerAttribute : AddressAttribute
{
    public AlternateServerAttribute()
    {
        Type = AttributeType.AlternateServer;
    }

    public static AlternateServerAttribute FromGenericAttribute(MessageAttribute attr)
    {
        // Parse address like other address attributes
    }
}
```

#### 11.2 Server Configuration for Alternates

Update `StunServerConfiguration.cs`:

```csharp
public class AlternateServerConfig
{
    public IPAddress Address { get; set; }
    public int Port { get; set; }
    public int Weight { get; set; } = 1;  // For weighted load balancing
}

public class StunServerConfiguration
{
    // ...
    public List<AlternateServerConfig> AlternateServers { get; set; }
    public bool IncludeAlternateInResponses { get; set; } = false;
}
```

#### 11.3 Update Server Response Generation

Update `StunUdpServer.cs`:

```csharp
// In ProcessingLoop, when building response:
if (_config.IncludeAlternateInResponses && _config.AlternateServers?.Any() == true)
{
    foreach (var alternate in _config.AlternateServers)
    {
        attributeList.Add(new AlternateServerAttribute
        {
            AddressFamily = alternate.Address.AddressFamily,
            IPAddress = alternate.Address,
            Port = (ushort)alternate.Port
        });
    }
}
```

#### 11.4 Client Handling of ALTERNATE-SERVER

When client receives error 300 (Try Alternate), automatically retry with alternate:

```csharp
public async Task<MessageResponse> BindingRequestWithFailoverAsync(...)
{
    var response = await BindingRequestAsync(...);

    if (!response.Success && response.Message.Header.Type == MessageType.BindingError)
    {
        var errorCode = response.Message.Attributes?
            .OfType<ErrorCodeAttribute>()
            .FirstOrDefault();

        if (errorCode?.ErrorCode == 300)
        {
            var alternate = response.Message.Attributes?
                .OfType<AlternateServerAttribute>()
                .FirstOrDefault();

            if (alternate != null)
            {
                using var altClient = new StunUdpClient(
                    alternate.IPAddress.ToString(),
                    alternate.Port);
                return await altClient.BindingRequestAsync(...);
            }
        }
    }

    return response;
}
```

#### 11.5 OTHER-ADDRESS for NAT Detection

The server should include OTHER-ADDRESS to support RFC 5780 NAT detection:

```csharp
// When server has multiple addresses/ports configured:
if (_config.OtherAddress != null)
{
    attributeList.Add(new OtherAddressAttribute
    {
        AddressFamily = _config.OtherAddress.AddressFamily,
        IPAddress = _config.OtherAddress,
        Port = (ushort)_config.OtherPort
    });
}
```

#### 11.6 RESPONSE-ORIGIN

Include RESPONSE-ORIGIN to indicate which server address sent the response:

```csharp
attributeList.Add(new ResponseOriginAttribute
{
    AddressFamily = localEndpoint.AddressFamily,
    IPAddress = localEndpoint.Address,
    Port = (ushort)localEndpoint.Port
});
```

### Affected Files

| File | Changes |
|------|---------|
| `common/core/AlternateServerAttribute.cs` | New file |
| `common/core/OtherAddressAttribute.cs` | New file (if not using AddressAttribute) |
| `common/core/ResponseOriginAttribute.cs` | New file (if not using AddressAttribute) |
| `common/core/MessageAttribute.cs` | Add parsing for new types |
| `common/config/StunServerConfiguration.cs` | Add alternate config |
| `common/server/StunUdpServer.cs` | Include alternates in response |
| `common/client/StunUdpClient.cs` | Handle 300 error, failover |

---

## Implementation Priority Matrix

| Enhancement | Effort | Impact | Dependencies | Suggested Order |
|------------|--------|--------|--------------|-----------------|
| 3. Error Response Handling | Low | High | None | 1 |
| 8. Test Coverage | Medium | High | None | 2 |
| 1. STUN Authentication | High | Critical | #3 | 3 |
| 2. TCP Server | Medium | Medium | None | 4 |
| 11. Alternate Server | Low | Medium | None | 5 |
| 9. Configuration & Observability | Medium | High | None | 6 |
| 10. IPv6 Improvements | Low | Medium | #8 | 7 |
| 4. RFC 5780 NAT Discovery | Medium | Medium | #11 | 8 |
| 6. TLS/DTLS Transport | High | High | #2 | 9 |
| 7. ICE Support | High | High | #1, #6 | 10 |
| 5. TURN Support | Very High | Critical | #1, #7 | 11 |

---

## Quick Reference: RFC Compliance Checklist

### RFC 5389 (STUN)

- [ ] MESSAGE-INTEGRITY (HMAC-SHA1)
- [ ] FINGERPRINT (CRC-32)
- [ ] Short-term credentials
- [ ] Long-term credentials
- [ ] Error responses (400, 401, 420, 438, 500)
- [ ] UNKNOWN-ATTRIBUTES
- [ ] TCP framing
- [ ] TLS support

### RFC 5766 (TURN)

- [ ] Allocate request/response
- [ ] Refresh request/response
- [ ] CreatePermission request/response
- [ ] ChannelBind request/response
- [ ] Send indication
- [ ] Data indication
- [ ] Channel data messages

### RFC 5780 (NAT Behavior Discovery)

- [ ] Mapping behavior detection
- [ ] Filtering behavior detection
- [ ] RESPONSE-ORIGIN
- [ ] OTHER-ADDRESS

### RFC 8445 (ICE)

- [ ] PRIORITY attribute
- [ ] USE-CANDIDATE attribute
- [ ] ICE-CONTROLLED attribute
- [ ] ICE-CONTROLLING attribute
- [ ] Connectivity checks
- [ ] Candidate gathering
