using System;
using System.CommandLine;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using stungun.common.client;
using stungun.common.core;

namespace stungun.client;

class Program
{
    public static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("STUN/TURN client for NAT traversal and discovery")
        {
            Name = "stun-client"
        };

        // Global options
        var hostOption = new Option<string>(
            aliases: ["--host", "-h"],
            description: "STUN server hostname or IP address",
            getDefaultValue: () => "stun.l.google.com");

        var portOption = new Option<int>(
            aliases: ["--port", "-p"],
            description: "STUN server port",
            getDefaultValue: () => 3478);

        var protocolOption = new Option<Protocol>(
            aliases: ["--protocol", "-t"],
            description: "Transport protocol to use",
            getDefaultValue: () => Protocol.Udp);

        var verboseOption = new Option<bool>(
            aliases: ["--verbose", "-v"],
            description: "Enable verbose output",
            getDefaultValue: () => false);

        // Bind command
        var bindCommand = new Command("bind", "Send a STUN binding request to discover external IP and port")
        {
            hostOption,
            portOption,
            protocolOption,
            verboseOption
        };

        bindCommand.SetHandler(async (context) =>
        {
            var host = context.ParseResult.GetValueForOption(hostOption)!;
            var port = context.ParseResult.GetValueForOption(portOption);
            var protocol = context.ParseResult.GetValueForOption(protocolOption);
            var verbose = context.ParseResult.GetValueForOption(verboseOption);
            var ct = context.GetCancellationToken();

            context.ExitCode = await ExecuteBindAsync(host, port, protocol, verbose, ct);
        });

        // Discover command
        var discoverCommand = new Command("discover", "Perform NAT type discovery")
        {
            hostOption,
            portOption,
            verboseOption
        };

        var rfcOption = new Option<NatDiscoveryRfc>(
            aliases: ["--rfc", "-r"],
            description: "RFC to use for NAT discovery",
            getDefaultValue: () => NatDiscoveryRfc.Rfc3489);

        discoverCommand.AddOption(rfcOption);

        discoverCommand.SetHandler(async (context) =>
        {
            var host = context.ParseResult.GetValueForOption(hostOption)!;
            var port = context.ParseResult.GetValueForOption(portOption);
            var rfc = context.ParseResult.GetValueForOption(rfcOption);
            var verbose = context.ParseResult.GetValueForOption(verboseOption);
            var ct = context.GetCancellationToken();

            context.ExitCode = await ExecuteDiscoverAsync(host, port, rfc, verbose, ct);
        });

        // Add a default behavior when no subcommand is specified
        rootCommand.AddCommand(bindCommand);
        rootCommand.AddCommand(discoverCommand);

        // Allow running without subcommand for quick binding request (backward compatibility)
        rootCommand.AddOption(hostOption);
        rootCommand.AddOption(portOption);
        rootCommand.AddOption(protocolOption);
        rootCommand.AddOption(verboseOption);

        rootCommand.SetHandler(async (context) =>
        {
            var host = context.ParseResult.GetValueForOption(hostOption)!;
            var port = context.ParseResult.GetValueForOption(portOption);
            var protocol = context.ParseResult.GetValueForOption(protocolOption);
            var verbose = context.ParseResult.GetValueForOption(verboseOption);
            var ct = context.GetCancellationToken();

            // Default behavior: run bind command
            context.ExitCode = await ExecuteBindAsync(host, port, protocol, verbose, ct);
        });

        return await rootCommand.InvokeAsync(args);
    }

    private static async Task<int> ExecuteBindAsync(
        string host,
        int port,
        Protocol protocol,
        bool verbose,
        CancellationToken ct)
    {
        if (verbose)
        {
            Console.WriteLine($"stun-client 2.0");
            Console.WriteLine($"Connecting to {host}:{port} via {protocol.ToString().ToUpperInvariant()}...");
        }

        IStunClient stunClient = protocol switch
        {
            Protocol.Tcp => new StunTcpClient(host, port),
            _ => new StunUdpClient(host, port)
        };

        using (stunClient)
        {
            try
            {
                var resp = await stunClient.BindingRequestAsync(cancellationToken: ct);

                if (verbose)
                {
                    Console.WriteLine($"Query: {resp.LocalEndpoint} -> {resp.RemoteEndpoint}");
                }

                if (resp.Success)
                {
                    var msg = resp.Message!;

                    if (verbose)
                    {
                        Console.WriteLine($"Response: {msg.Header.Type} ({(ushort)msg.Header.Type:X4})");
                        Console.WriteLine($"  Total length: {msg.Header.MessageLength + 20} bytes");
                        Console.WriteLine($"  Attributes: {msg.Attributes?.Count ?? 0}");
                        Console.WriteLine();
                    }

                    // Find and display the mapped address
                    if (msg.Attributes != null)
                    {
                        foreach (var attr in msg.Attributes)
                        {
                            if (verbose)
                            {
                                Console.WriteLine($"  [{attr.Type}] (0x{(ushort)attr.Type:X4})");
                                Console.WriteLine($"    {attr}");
                            }

                            // Display XOR-MAPPED-ADDRESS prominently (preferred per RFC 5389)
                            if (attr is XorMappedAddressAttribute xorAddr)
                            {
                                Console.WriteLine($"External Address: {xorAddr.IPAddress}:{xorAddr.Port}");
                            }
                            // Fallback to MAPPED-ADDRESS if no XOR-MAPPED-ADDRESS
                            else if (attr is MappedAddressAttribute mappedAddr &&
                                     !msg.Attributes.Any(a => a is XorMappedAddressAttribute))
                            {
                                Console.WriteLine($"External Address: {mappedAddr.IPAddress}:{mappedAddr.Port}");
                            }
                        }
                    }

                    return 0;
                }
                else
                {
                    Console.Error.WriteLine($"Error: {resp.ErrorMessage}");
                    return 1;
                }
            }
            catch (OperationCanceledException)
            {
                Console.Error.WriteLine("Operation cancelled.");
                return 130;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                if (verbose)
                {
                    Console.Error.WriteLine(ex.ToString());
                }
                return 1;
            }
        }
    }

    private static async Task<int> ExecuteDiscoverAsync(
        string host,
        int port,
        NatDiscoveryRfc rfc,
        bool verbose,
        CancellationToken ct)
    {
        if (verbose)
        {
            Console.WriteLine($"stun-client 2.0");
            Console.WriteLine($"Performing NAT discovery via {host}:{port} using {rfc}...");
        }

        try
        {
            var disco = new DiscoveryClient(host, port);

            if (rfc == NatDiscoveryRfc.Rfc5780)
            {
                var (mapping, filtering) = await disco.DiscoverUdpRfc5780Async(ct);
                Console.WriteLine($"NAT Mapping Behavior:   {mapping}");
                Console.WriteLine($"NAT Filtering Behavior: {filtering}");

                if (mapping == NatMappingTypeRfc5780.Unknown || filtering == NatFilteringTypeRfc5780.Unknown)
                {
                    Console.WriteLine();
                    Console.WriteLine("Note: RFC 5780 discovery requires server support for CHANGE-REQUEST.");
                    Console.WriteLine("      Try using --rfc rfc3489 for basic NAT type detection.");
                }
            }
            else
            {
                var natType = await disco.DiscoverUdpRfc3489Async(ct);
                Console.WriteLine($"NAT Type: {natType}");

                if (verbose)
                {
                    Console.WriteLine();
                    Console.WriteLine(GetNatTypeDescription(natType));
                }
            }

            return 0;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Operation cancelled.");
            return 130;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            if (verbose)
            {
                Console.Error.WriteLine(ex.ToString());
            }
            return 1;
        }
    }

    private static string GetNatTypeDescription(NatTypeRfc3489 natType)
    {
        return natType switch
        {
            NatTypeRfc3489.OpenInternet =>
                "No NAT detected. Your device has a public IP address.",
            NatTypeRfc3489.FullCone =>
                "Full Cone NAT. Any external host can send packets through the mapped port.",
            NatTypeRfc3489.RestrictedCone =>
                "Restricted Cone NAT. External hosts you've sent to can reply from any port.",
            NatTypeRfc3489.PortRestrictedCone =>
                "Port Restricted Cone NAT. External hosts can only reply from the same port.",
            NatTypeRfc3489.SymmetricNat =>
                "Symmetric NAT. A different mapping is used for each destination. P2P may be difficult.",
            NatTypeRfc3489.SymmetricUdpFirewall =>
                "Symmetric UDP Firewall. No NAT, but firewall restricts incoming connections.",
            NatTypeRfc3489.UdpBlocked =>
                "UDP is blocked. Cannot establish UDP connections through this network.",
            _ =>
                "Unable to determine NAT type."
        };
    }
}

public enum Protocol
{
    Udp,
    Tcp
}

public enum NatDiscoveryRfc
{
    Rfc3489,
    Rfc5780
}
