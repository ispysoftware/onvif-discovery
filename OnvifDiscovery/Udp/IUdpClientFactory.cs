namespace OnvifDiscovery.Udp;

/// <summary>
///     Factory to create <see cref="IUdpClient" /> clients
/// </summary>
public interface IUdpClientFactory
{
    /// <summary>
    ///     Creates an <see cref="IUdpClient" /> for each valid network interface
    /// </summary>
    /// <returns>A list of <see cref="IUdpClient" /></returns>
    IEnumerable<IUdpClient> CreateClientForeachInterface();

    /// <summary>
    ///     Creates a single <see cref="IUdpClient" /> bound to any address, suitable for sending
    ///     unicast probes to routed (off-link) targets — the OS picks the outgoing interface per target.
    /// </summary>
    IUdpClient CreateClient();
}