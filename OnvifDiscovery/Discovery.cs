using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using OnvifDiscovery.Common;
using OnvifDiscovery.Exceptions;
using OnvifDiscovery.Models;
using OnvifDiscovery.Udp;

namespace OnvifDiscovery;

/// <summary>
///     Onvif Discovery, has the logic to discover onvif compliant devices on the network
/// </summary>
public class Discovery : IDiscovery
{
    private readonly IUdpClientFactory clientFactory;

    /// <summary>
    ///     Creates an instance of <see cref="Discovery" />
    /// </summary>
    public Discovery() : this(new UdpClientFactory())
    { }

    /// <summary>
    ///     Creates an instance of <see cref="Discovery" />
    /// </summary>
    /// <param name="clientFactory">An UDP client factory instance</param>
    public Discovery(IUdpClientFactory clientFactory)
    {
        this.clientFactory = clientFactory;
    }

    /// <summary>
    ///     Discover new onvif cameras by returning an async enumerable
    /// </summary>
    /// <param name="timeout">A timeout in seconds to wait for onvif devices</param>
    /// <param name="cancellationToken">A cancellation token</param>
    /// <returns></returns>
    public IAsyncEnumerable<DiscoveryDevice> DiscoverAsync(int timeout, CancellationToken cancellationToken = default)
    {
        var channel = Channel.CreateUnbounded<DiscoveryDevice>();
        _ = DiscoverFromAllInterfaces(channel.Writer, timeout, cancellationToken);
        return channel.Reader.ReadAllAsync(cancellationToken);
    }

    /// <summary>
    ///     Discover new onvif cameras by passing a channel writer and a timeout
    /// </summary>
    /// <param name="channelWriter">Channel Writer that this method will use to write new discovered cameras</param>
    /// <param name="timeout">A timeout in seconds to wait for onvif devices</param>
    /// <param name="cancellationToken">A cancellation token</param>
    /// <returns></returns>
    public Task DiscoverAsync(ChannelWriter<DiscoveryDevice> channelWriter, int timeout,
        CancellationToken cancellationToken = default) =>
        DiscoverFromAllInterfaces(channelWriter, timeout, cancellationToken);

    /// <summary>
    ///     Discover new onvif devices on the network passing a callback
    ///     to retrieve devices as they reply
    /// </summary>
    /// <param name="timeout">A timeout in seconds to wait for onvif devices</param>
    /// <param name="onDeviceDiscovered">A method that is called each time a new device replies.</param>
    /// <param name="cancellationToken">A cancellation token</param>
    /// <returns>The Task to be awaited</returns>
    [Obsolete("Use one of the DiscoverAsync methods, this method will be removed in next major release")]
    public async Task Discover(int timeout, Action<DiscoveryDevice> onDeviceDiscovered,
        CancellationToken cancellationToken = default)
    {
        await foreach (var discoveredDevice in DiscoverAsync(timeout, cancellationToken))
        {
            onDeviceDiscovered(discoveredDevice);
        }
    }

    /// <summary>
    ///     Discover new onvif devices on the network
    /// </summary>
    /// <param name="timeout">A timeout in seconds to wait for onvif devices</param>
    /// <param name="cancellationToken">A cancellation token</param>
    /// <returns>a list of <see cref="DiscoveryDevice" /></returns>
    /// <remarks>
    ///     Use the <see cref="Discover(int, Action{DiscoveryDevice}, CancellationToken)" />
    ///     overload (with an action as a parameter) if you want to retrieve devices as they reply.
    /// </remarks>
    [Obsolete("Use one of the DiscoverAsync methods, this method will be removed in next major release")]
    public async Task<IEnumerable<DiscoveryDevice>> Discover(int timeout,
        CancellationToken cancellationToken = default)
    {
        var devices = new List<DiscoveryDevice>();
        await foreach (var discoveredDevice in DiscoverAsync(timeout, cancellationToken))
        {
            devices.Add(discoveredDevice);
        }

        return devices;
    }

    /// <summary>
    ///     Discover onvif devices at specific addresses by probing them directly (unicast).
    ///     WS-Discovery multicast never crosses a router, but ONVIF devices also answer a probe sent
    ///     unicast to udp/3702 — this reaches devices on routable subnets (other VLANs, behind a
    ///     second router, over a VPN). Pass the candidate addresses to sweep.
    /// </summary>
    /// <param name="addresses">Candidate device addresses to probe (typically host addresses of routable subnets)</param>
    /// <param name="timeout">A timeout in seconds to wait for onvif devices</param>
    /// <param name="cancellationToken">A cancellation token</param>
    public IAsyncEnumerable<DiscoveryDevice> DiscoverUnicastAsync(IEnumerable<IPAddress> addresses, int timeout,
        CancellationToken cancellationToken = default)
    {
        var channel = Channel.CreateUnbounded<DiscoveryDevice>();
        _ = DiscoverUnicast(channel.Writer, addresses, timeout, cancellationToken);
        return channel.Reader.ReadAllAsync(cancellationToken);
    }

    private async Task DiscoverUnicast(ChannelWriter<DiscoveryDevice> channelWriter,
        IEnumerable<IPAddress> addresses, int timeout, CancellationToken cancellationToken)
    {
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(timeout));
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
        try
        {
            var targets = addresses.Select(a => new IPEndPoint(a, Constants.WS_MULTICAST_PORT)).ToArray();
            if (targets.Length == 0)
            {
                return;
            }

            using var client = clientFactory.CreateClient();
            try
            {
                var messageId = Guid.NewGuid();
                var discoveredDevicesAddresses = new ConcurrentDictionary<string, bool>();
                var probeTask = SendUnicastProbeMessages(client, targets, messageId, timeout, cts.Token);
                var receiveTask = ReceiveDiscoverMessages(channelWriter, client, discoveredDevicesAddresses,
                    messageId, cts.Token);
                await Task.WhenAll(probeTask, receiveTask);
            } finally
            {
                client.Close();
            }
        } catch (Exception ex) when (ex is OperationCanceledException or TaskCanceledException &&
                                     timeoutCts.IsCancellationRequested)
        {
            // If cancellation is from timeout source then just catch it
        } catch (Exception ex)
        {
            channelWriter.TryComplete(ex);
            throw;
        } finally
        {
            channelWriter.TryComplete();
        }
    }

    private const int ProbePasses = 2;
    private const int ProbeBatchSize = 32;
    private const int InterPassDelayMs = 1000;

    private static async Task SendUnicastProbeMessages(IUdpClient client, IPEndPoint[] targets, Guid messageId,
        int timeoutSeconds, CancellationToken cancellationToken)
    {
        var datagram = WSProbeMessageBuilder.NewProbeMessage(messageId);

        // Self-limiting pacing: every probe to a dead address costs the host an ARP/neighbour entry,
        // and behind a user-space NAT (rootless podman/slirp4netns, pasta) a burst of a few hundred
        // stalls the container's live RTSP streams long enough to drop them. So instead of a fixed
        // rate, spread each pass across its share of the timeout window (two passes plus a gap plus
        // reply time), with a floor so small lists are still spaced and a ceiling so a handful of
        // targets doesn't crawl.
        var batches = Math.Max(1, (targets.Length + ProbeBatchSize - 1) / ProbeBatchSize);
        var perPassMs = Math.Max(0, timeoutSeconds * 1000 - InterPassDelayMs * (ProbePasses - 1)) * 0.35;
        var batchDelayMs = Math.Clamp((int)(perPassMs / batches), 50, 500);

        // Two passes only (UDP is lossy; a busy camera can miss one), then leave the socket to
        // collect replies until the timeout window closes. Re-probing every second for the whole
        // window multiplied a /24 sweep into thousands of datagrams.
        for (var pass = 0; pass < ProbePasses && !cancellationToken.IsCancellationRequested; pass++)
        {
            if (pass > 0)
            {
                await Task.Delay(InterPassDelayMs, cancellationToken);
            }

            var sent = 0;
            foreach (var target in targets)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    await client.SendAsync(datagram, target, cancellationToken);
                } catch (SocketException)
                {
                    // target/network unreachable — keep sweeping the rest
                }

                if (++sent % ProbeBatchSize == 0 && sent < targets.Length)
                {
                    await Task.Delay(batchDelayMs, cancellationToken);
                }
            }
        }
    }

    private async Task DiscoverFromAllInterfaces(ChannelWriter<DiscoveryDevice> channelWriter, int timeout,
        CancellationToken cancellationToken)
    {
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(timeout));
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
        try
        {
            var clients = clientFactory.CreateClientForeachInterface().ToArray();
            if (!clients.Any())
            {
                throw new DiscoveryException("Missing valid NetworkInterfaces, UdpClients could not be created");
            }

            var discoveredDevicesAddresses = new ConcurrentDictionary<string, bool>();
            var discoveries = clients.Select(client =>
                DiscoverFromSingleInterface(channelWriter, client, discoveredDevicesAddresses, cts.Token));
            await Task.WhenAll(discoveries);
        } catch (Exception ex) when (ex is OperationCanceledException or TaskCanceledException &&
                                     timeoutCts.IsCancellationRequested)
        {
            // If cancellation is from timeout source then just catch it
        } catch (Exception ex)
        {
            channelWriter.TryComplete(ex);
            throw;
        } finally
        {
            channelWriter.TryComplete();
        }
    }

    private static async Task DiscoverFromSingleInterface(ChannelWriter<DiscoveryDevice> channelWriter,
        IUdpClient client, ConcurrentDictionary<string, bool> discoveredDevicesAddresses,
        CancellationToken cancellationToken)
    {
        try
        {
            var messageId = Guid.NewGuid();
            var probeTask = SendProbeMessages(client, messageId, cancellationToken);
            var discoverMessagesTask =
                ReceiveDiscoverMessages(channelWriter, client, discoveredDevicesAddresses, messageId,
                    cancellationToken);
            await Task.WhenAll(probeTask, discoverMessagesTask);
        } finally
        {
            client.Close();
        }
    }

    private static async Task SendProbeMessages(IUdpClient client, Guid messageId, CancellationToken cancellationToken)
    {
        var multicastEndpoint =
            new IPEndPoint(IPAddress.Parse(Constants.WS_MULTICAST_ADDRESS), Constants.WS_MULTICAST_PORT);
        var datagram = WSProbeMessageBuilder.NewProbeMessage(messageId);
        while (!cancellationToken.IsCancellationRequested)
        {
            await client.SendAsync(datagram, multicastEndpoint, cancellationToken);
            await Task.Delay(500, cancellationToken);
        }
    }

    private static async Task ReceiveDiscoverMessages(ChannelWriter<DiscoveryDevice> channelWriter,
        IUdpClient client, ConcurrentDictionary<string, bool> discoveredDevicesAddresses, Guid messageId,
        CancellationToken cancellationToken)
    {
        await foreach (var response in client.ReceiveResultsAsync(cancellationToken))
        {
            var discoveredDevice = ProbeMessageProcessor.ProcessResponse(response, messageId);
            if (discoveredDevice is null || discoveredDevice.XAddresses.All(discoveredDevicesAddresses.ContainsKey))
            {
                continue;
            }

            foreach (var xAddress in discoveredDevice.XAddresses)
            {
                discoveredDevicesAddresses.TryAdd(xAddress, true);
            }

            await channelWriter.WriteAsync(discoveredDevice, cancellationToken);
        }
    }
}