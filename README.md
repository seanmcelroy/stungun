stungun
======

A .NET Core implementation of the STUN protocol based on IETF RFC 5389.

```./client``` contains a sample STUN client that can connect to a STUN server
over either UDP or TCP.  It is a simple wrapper around the classlib components.
This is a console-based application.

```./common``` is the classlib that contains the core message and attribute
components, as well as the client and server protocol implementations.  If you
want to implement your own STUN agent, this project contains the classes you
will want.  This classlib also includes a DiscoveryClient, which implements
the three-test procedure described in RFC 3489.

```./common.tests``` is a set of unit tests that validate the functionality
in the common classlib.

```./server``` contains a very simple UDP STUN server.  It will respond to STUN
requests with the MappedAttribute and XorMappedAttribute attributes.  Building
the project and running it with ```dotnet run --project server/``` will start the server.

Pull requests or questions are welcome!

# Standards compliance

This project aims to provide compliance with the following RFCs:

- RFC3489: STUN - Simple Traversal of User Datagram Protocol (UDP)Through Network Address Translators (NATs)
- RFC5245: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal for Offer/Answer Protocols
- RFC5389: Session Traversal Utilities for NAT (STUN)
- RFC5626: Managing Client Initiated Connections in the Session Initiation Protocol (SIP)
- RFC5766: Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)
- RFC5780: NAT Behavior Discovery Using STUN
- RFC5853: Test vectors for STUN
- RFC6062: Traversal Using Relays around NAT (TURN) Extensions for TCP Allocations
- RFC6156: Traversal Using Relays around NAT (TURN) Extension for IPv4/IPv6 Transition
- RFC6679: Explicit Congestion Notification (ECN) for RTP over UDP
