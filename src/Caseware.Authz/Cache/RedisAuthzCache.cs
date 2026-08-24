using System.Collections.Concurrent;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;

namespace Caseware.Authz.Cache;

public sealed class RedisAuthzCache : IAuthzCache, IAsyncDisposable
{
    private static readonly ConcurrentDictionary<string, RedisAuthzCache> Connections = new(StringComparer.Ordinal);

    private readonly string _host;
    private readonly int _port;
    private readonly bool _useTls;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private TcpClient? _client;
    private Stream? _stream;

    public RedisAuthzCache(string endpoint, bool useTls = false)
    {
        var parts = endpoint.Split(':');
        _host = parts[0];
        _port = parts.Length > 1 && int.TryParse(parts[1], out var p) ? p : 6379;
        _useTls = useTls;
    }

    public int GetCalls { get; private set; }
    public int SetCalls { get; private set; }
    public int DeleteCalls { get; private set; }

    public static RedisAuthzCache Connect(string endpoint, bool useTls = false) => new(endpoint, useTls);

    public static RedisAuthzCache Shared(string endpoint, bool useTls = false)
        => Connections.GetOrAdd(
            endpoint + (useTls ? "|tls" : ""),
            _ => new RedisAuthzCache(endpoint, useTls));

    public async ValueTask<CacheLookup> GetAsync(string jti, CancellationToken cancellationToken)
    {
        GetCalls++;
        var raw = await CallAsync(["GET", KeyString(jti)], cancellationToken).ConfigureAwait(false);
        if (raw is null)
        {
            return new CacheLookup(CacheOutcome.Miss);
        }

        if (raw == AuthorizerOptions.DenySentinelValue)
        {
            return new CacheLookup(CacheOutcome.DenySentinel);
        }

        return new CacheLookup(CacheOutcome.Allow, raw);
    }

    public async ValueTask SetAllowAsync(string jti, string roles, TimeSpan ttl, CancellationToken cancellationToken)
    {
        SetCalls++;
        var seconds = Math.Max(1, (int)ttl.TotalSeconds);
        await CallAsync(["SET", KeyString(jti), roles, "EX", seconds.ToString()], cancellationToken)
            .ConfigureAwait(false);
    }

    public async ValueTask SetDenySentinelAsync(string jti, TimeSpan ttl, CancellationToken cancellationToken)
    {
        SetCalls++;
        var seconds = Math.Max(1, (int)ttl.TotalSeconds);
        await CallAsync(["SET", KeyString(jti), AuthorizerOptions.DenySentinelValue, "EX", seconds.ToString()], cancellationToken)
            .ConfigureAwait(false);
    }

    public async ValueTask DeleteAsync(string jti, CancellationToken cancellationToken)
    {
        DeleteCalls++;
        await CallAsync(["DEL", KeyString(jti)], cancellationToken).ConfigureAwait(false);
    }

    public async Task<string> PingAsync(CancellationToken cancellationToken)
        => await CallAsync(["PING"], cancellationToken).ConfigureAwait(false) ?? "";

    public async Task<long> PttlMillisecondsAsync(string jti, CancellationToken cancellationToken)
    {
        var raw = await CallAsync(["PTTL", KeyString(jti)], cancellationToken).ConfigureAwait(false);
        return long.TryParse(raw, out var ms) ? ms : -2;
    }

    private static string KeyString(string jti) => "authz:" + jti;

    private async Task<string?> CallAsync(string[] parts, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
            var payload = Encode(parts);
            await _stream!.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
            return await ReadAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task EnsureConnectedAsync(CancellationToken cancellationToken)
    {
        if (_client is { Connected: true } && _stream is not null)
        {
            return;
        }

        _client?.Dispose();
        _stream?.Dispose();
        _client = new TcpClient();
        await _client.ConnectAsync(_host, _port, cancellationToken).ConfigureAwait(false);
        Stream stream = _client.GetStream();
        if (_useTls)
        {
            var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
            await ssl.AuthenticateAsClientAsync(
                    new SslClientAuthenticationOptions { TargetHost = _host },
                    cancellationToken)
                .ConfigureAwait(false);
            stream = ssl;
        }

        _stream = stream;
    }

    private static byte[] Encode(string[] parts)
    {
        var sb = new StringBuilder();
        sb.Append('*').Append(parts.Length).Append("\r\n");
        foreach (var part in parts)
        {
            var bytes = Encoding.UTF8.GetByteCount(part);
            sb.Append('$').Append(bytes).Append("\r\n").Append(part).Append("\r\n");
        }

        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private async Task<string?> ReadAsync(CancellationToken cancellationToken)
    {
        var buffer = new byte[8192];
        var n = await _stream!.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
        if (n <= 0)
        {
            return null;
        }

        var text = Encoding.UTF8.GetString(buffer, 0, n);
        if (text.StartsWith("$-1", StringComparison.Ordinal))
        {
            return null;
        }

        if (text[0] == '+')
        {
            var end = text.IndexOf("\r\n", StringComparison.Ordinal);
            return end > 1 ? text[1..end] : text[1..];
        }

        if (text[0] == ':')
        {
            return text[1..].Trim();
        }

        if (text[0] == '$')
        {
            var nl = text.IndexOf("\r\n", StringComparison.Ordinal);
            if (nl < 0)
            {
                return null;
            }

            var payload = text[(nl + 2)..];
            var end = payload.IndexOf("\r\n", StringComparison.Ordinal);
            return end >= 0 ? payload[..end] : payload;
        }

        if (text[0] == '-')
        {
            throw new InvalidOperationException(text);
        }

        return text.Trim();
    }

    public async ValueTask DisposeAsync()
    {
        _stream?.Dispose();
        _client?.Dispose();
        _gate.Dispose();
        await Task.CompletedTask.ConfigureAwait(false);
    }
}
