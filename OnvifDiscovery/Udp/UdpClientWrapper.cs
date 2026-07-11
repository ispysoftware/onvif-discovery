using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;

namespace OnvifDiscovery.Udp;

/// <summary>
///     A simple Udp client that wraps <see cref="System.Net.Sockets.UdpClient" />
/// </summary>
[ExcludeFromCodeCoverage]
internal sealed class UdpClientWrapper : IUdpClient
{
    private readonly UdpClient client;
    private bool disposedValue;

    public UdpClientWrapper(IPEndPoint localEndpoint)
    {
        client = new UdpClient(localEndpoint)
        {
            EnableBroadcast = true
        };

        if (OperatingSystem.IsWindows())
        {
            // Unicast probes to dead addresses come back as ICMP port-unreachable, which Windows
            // surfaces as a socket error on the NEXT ReceiveAsync — one dead target would then
            // poison receives for live ones. SIO_UDP_CONNRESET disables that behaviour.
            try
            {
                client.Client.IOControl(unchecked((int)0x9800000C) /* SIO_UDP_CONNRESET */,
                    new byte[] { 0 }, null);
            } catch
            {
                // best effort — receive loop also swallows per-datagram errors
            }
        }

        try
        {
            // Default multicast TTL is 1; a slightly larger scope lets probes cross routers that
            // are configured to forward multicast (IGMP proxy / PIM), which the default never can.
            client.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 4);
        } catch
        {
            // not fatal — link-local discovery still works
        }
    }

    public async Task<int> SendAsync(byte[] datagram, IPEndPoint endPoint, CancellationToken cancellationToken)
        => await client.SendAsync(datagram, datagram.Length, endPoint);

    public async IAsyncEnumerable<UdpReceiveResult> ReceiveResultsAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            UdpReceiveResult? response = null;
            try
            {
                response = await client.ReceiveAsync(cancellationToken);
            } catch (Exception ex) when (ex is TaskCanceledException or OperationCanceledException)
            {
                throw;
            } catch (Exception)
            {
                // we catch all other exceptions !
                // Something might be bad in the response of a camera when call ReceiveAsync (BeginReceive in socket) fail
            }

            if (response.HasValue)
            {
                yield return response.Value;
            }
        }
    }

    public void Close()
    {
        client.Close();
    }

    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            if (disposing)
            {
                client.Close();
                client.Dispose();
            }

            disposedValue = true;
        }
    }
}