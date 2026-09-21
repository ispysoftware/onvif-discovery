using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using OnvifDiscovery.Common;

namespace OnvifDiscovery;

/// <summary>
///     Passively listens for ONVIF WS-Discovery "Hello" announcements (devices joining the network) on the
///     discovery multicast group, complementing the active probe-based <see cref="Discovery" />. Lets callers
///     react to a newly-connected device in seconds instead of waiting for the next probe.
/// </summary>
public sealed class WsDiscoveryListener : IDisposable
{
    private readonly IPAddress _group = IPAddress.Parse(Constants.WS_MULTICAST_ADDRESS);
    private UdpClient? _udp;
    private CancellationTokenSource? _cts;

    /// <summary>Raised when a device announces itself with a Hello message.</summary>
    public event Action? HelloReceived;

    /// <summary>
    ///     Optional diagnostic sink — invoked for every datagram received on the group with a short
    ///     "from-ip kind" description. Lets a caller see whether any multicast is arriving at all
    ///     (firewall / bind / join working) versus the camera simply never sending a Hello.
    /// </summary>
    public Action<string>? Diagnostic;

    /// <summary>True once the listener has bound the multicast socket and is receiving.</summary>
    public bool IsListening => _udp != null;

    /// <summary>
    ///     Binds the WS-Discovery multicast group and begins listening. Safe to call once; subsequent calls
    ///     are no-ops. Binding can fail if another process already holds the port (e.g. the Windows Function
    ///     Discovery service) — in that case no exception escapes and the listener simply stays inactive.
    /// </summary>
    public void Start()
    {
        if (_udp != null)
            return;

        try
        {
            var udp = new UdpClient { ExclusiveAddressUse = false };
            udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            udp.Client.Bind(new IPEndPoint(IPAddress.Any, Constants.WS_MULTICAST_PORT));

            var joined = false;
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up)
                    continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork)
                        continue;
                    try
                    {
                        udp.JoinMulticastGroup(_group, ua.Address);
                        joined = true;
                    }
                    catch
                    {
                        // interface may not support multicast — ignore and try the next
                    }
                }
            }

            if (!joined)
            {
                try { udp.JoinMulticastGroup(_group); }
                catch { /* nothing to join on — listener will receive nothing, but won't throw */ }
            }

            _udp = udp;
            _cts = new CancellationTokenSource();
            _ = ListenAsync(udp, _cts.Token);
        }
        catch
        {
            // Port already held / not permitted — caller falls back to periodic probing.
            Stop();
        }
    }

    private async Task ListenAsync(UdpClient udp, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                var result = await udp.ReceiveAsync(token).ConfigureAwait(false);
                var text = Encoding.UTF8.GetString(result.Buffer);
                Diagnostic?.Invoke($"{result.RemoteEndPoint?.Address} {DescribeWsd(text)} ({result.Buffer.Length}b)");
                // Only react to Hello (a device joined). Probe/ProbeMatches/Bye traffic on the group is ignored.
                if (IsOnvifHello(text))
                    HelloReceived?.Invoke();
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch
            {
                // transient receive error — pause briefly and keep listening
                try { await Task.Delay(1000, token).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
            }
        }
    }

    // The group is shared with every other WS-Discovery speaker on the LAN — Windows PCs (Function
    // Discovery: wsdp:Device / pub:Computer), printers, NAS boxes. Windows re-sends Hello on every
    // interface whenever any local address changes, so a flapping adapter produces a storm of them.
    // Accept a Hello only if it names ONVIF (tdn:NetworkVideoTransmitter type, its onvif.org namespace,
    // or onvif:// scopes). Types is optional in a Hello, so one that carries no Types at all is let
    // through rather than risk missing a terse camera.
    private static bool IsOnvifHello(string text)
    {
        if (text.IndexOf("/Hello", StringComparison.OrdinalIgnoreCase) < 0)
            return false;
        if (text.IndexOf("NetworkVideoTransmitter", StringComparison.OrdinalIgnoreCase) >= 0
            || text.IndexOf("onvif", StringComparison.OrdinalIgnoreCase) >= 0)
            return true;
        return text.IndexOf(":Types", StringComparison.OrdinalIgnoreCase) < 0
               && text.IndexOf("<Types", StringComparison.OrdinalIgnoreCase) < 0;
    }

    // Cheap classification of a WS-Discovery datagram by its SOAP Action, for the diagnostic sink.
    private static string DescribeWsd(string text)
    {
        if (text.IndexOf("/Hello", StringComparison.OrdinalIgnoreCase) >= 0) return "Hello";
        if (text.IndexOf("/Bye", StringComparison.OrdinalIgnoreCase) >= 0) return "Bye";
        if (text.IndexOf("/ProbeMatches", StringComparison.OrdinalIgnoreCase) >= 0) return "ProbeMatches";
        if (text.IndexOf("/Probe", StringComparison.OrdinalIgnoreCase) >= 0) return "Probe";
        if (text.IndexOf("/ResolveMatches", StringComparison.OrdinalIgnoreCase) >= 0) return "ResolveMatches";
        if (text.IndexOf("/Resolve", StringComparison.OrdinalIgnoreCase) >= 0) return "Resolve";
        return "other";
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { }
        try { _udp?.Dispose(); } catch { }
        _udp = null;
        _cts = null;
    }

    public void Dispose() => Stop();
}
