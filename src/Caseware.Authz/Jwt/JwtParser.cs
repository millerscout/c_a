using System.Text;

namespace Caseware.Authz.Jwt;

public readonly struct JwtClaims
{
    public JwtClaims(string kid, string sub, string azp, string jti, long nbf, long exp, string iss)
    {
        Kid = kid;
        Sub = sub;
        Azp = azp;
        Jti = jti;
        Nbf = nbf;
        Exp = exp;
        Iss = iss;
    }

    public string Kid { get; }
    public string Sub { get; }
    public string Azp { get; }
    public string Jti { get; }
    public long Nbf { get; }
    public long Exp { get; }
    public string Iss { get; }
}

public static class Bearer
{
    public static bool TryGetToken(ReadOnlySpan<char> authorization, out ReadOnlySpan<char> token)
    {
        const string prefix = "Bearer ";
        if (authorization.IsEmpty)
        {
            token = default;
            return false;
        }

        if (authorization.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            token = authorization[prefix.Length..].Trim();
            return !token.IsEmpty;
        }

        token = default;
        return false;
    }
}

public static class JwtParser
{
    public static bool TryParseUnverified(ReadOnlySpan<char> jwt, out JwtClaims claims, out int signedLength, out int signatureStart)
    {
        claims = default;
        signedLength = 0;
        signatureStart = 0;

        var firstDot = jwt.IndexOf('.');
        if (firstDot <= 0)
        {
            return false;
        }

        var rest = jwt[(firstDot + 1)..];
        var secondDot = rest.IndexOf('.');
        if (secondDot <= 0)
        {
            return false;
        }

        signedLength = firstDot + 1 + secondDot;
        signatureStart = signedLength + 1;
        if (signatureStart >= jwt.Length)
        {
            return false;
        }

        var header = jwt[..firstDot];
        var payload = jwt[(firstDot + 1)..signedLength];

        if (!TryDecodeJson(header, out var headerJson) || !TryDecodeJson(payload, out var payloadJson))
        {
            return false;
        }

        if (!TryReadKid(headerJson, out var kid) || kid.Length == 0)
        {
            return false;
        }

        if (!TryReadPayload(payloadJson, out var sub, out var azp, out var jti, out var nbf, out var exp, out var iss))
        {
            return false;
        }

        claims = new JwtClaims(kid, sub, azp, jti, nbf, exp, iss);
        return true;
    }

    private static bool TryDecodeJson(ReadOnlySpan<char> b64, out byte[] json)
    {
        json = [];
        var decoded = Base64Url.Decode(b64);
        if (decoded.Length == 0)
        {
            return false;
        }

        json = decoded;
        return true;
    }

    private static bool TryReadKid(ReadOnlySpan<byte> json, out string kid)
    {
        kid = "";
        try
        {
            var reader = new System.Text.Json.Utf8JsonReader(json);
            while (reader.Read())
            {
                if (reader.TokenType != System.Text.Json.JsonTokenType.PropertyName)
                {
                    continue;
                }

                if (reader.ValueTextEquals("kid"u8) && reader.Read() && reader.TokenType == System.Text.Json.JsonTokenType.String)
                {
                    kid = reader.GetString() ?? "";
                    return kid.Length > 0;
                }
            }
        }
        catch (System.Text.Json.JsonException)
        {
            return false;
        }

        return false;
    }

    private static bool TryReadPayload(
        ReadOnlySpan<byte> json,
        out string sub,
        out string azp,
        out string jti,
        out long nbf,
        out long exp,
        out string iss)
    {
        sub = "";
        azp = "";
        jti = "";
        nbf = 0;
        exp = 0;
        iss = "";
        var clientId = "";

        try
        {
            var reader = new System.Text.Json.Utf8JsonReader(json);
            while (reader.Read())
            {
                if (reader.TokenType != System.Text.Json.JsonTokenType.PropertyName)
                {
                    continue;
                }

                if (reader.ValueTextEquals("sub"u8) && reader.Read())
                {
                    sub = reader.GetString() ?? "";
                }
                else if (reader.ValueTextEquals("azp"u8) && reader.Read())
                {
                    azp = reader.GetString() ?? "";
                }
                else if (reader.ValueTextEquals("client_id"u8) && reader.Read())
                {
                    clientId = reader.GetString() ?? "";
                }
                else if (reader.ValueTextEquals("jti"u8) && reader.Read())
                {
                    jti = reader.GetString() ?? "";
                }
                else if (reader.ValueTextEquals("iss"u8) && reader.Read())
                {
                    iss = reader.GetString() ?? "";
                }
                else if (reader.ValueTextEquals("nbf"u8) && reader.Read())
                {
                    nbf = ReadLong(ref reader);
                }
                else if (reader.ValueTextEquals("exp"u8) && reader.Read())
                {
                    exp = ReadLong(ref reader);
                }
            }
        }
        catch (System.Text.Json.JsonException)
        {
            return false;
        }

        if (azp.Length == 0)
        {
            azp = clientId;
        }

        return sub.Length > 0 && jti.Length > 0 && exp > 0;
    }

    private static long ReadLong(ref System.Text.Json.Utf8JsonReader reader)
    {
        return reader.TokenType switch
        {
            System.Text.Json.JsonTokenType.Number => reader.TryGetInt64(out var n) ? n : 0,
            System.Text.Json.JsonTokenType.String => long.TryParse(reader.GetString(), out var s) ? s : 0,
            _ => 0
        };
    }
}

public static class Base64Url
{
    public static byte[] Decode(ReadOnlySpan<char> input)
    {
        if (input.IsEmpty)
        {
            return [];
        }

        var pad = (4 - (input.Length % 4)) % 4;
        var chars = new char[input.Length + pad];
        input.CopyTo(chars);
        for (var i = 0; i < input.Length; i++)
        {
            chars[i] = chars[i] switch
            {
                '-' => '+',
                '_' => '/',
                _ => chars[i]
            };
        }

        for (var i = 0; i < pad; i++)
        {
            chars[input.Length + i] = '=';
        }

        try
        {
            return Convert.FromBase64CharArray(chars, 0, chars.Length);
        }
        catch (FormatException)
        {
            return [];
        }
    }

    public static string Encode(ReadOnlySpan<byte> data)
    {
        var s = Convert.ToBase64String(data);
        return s.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static string EncodeUtf8(string value) => Encode(Encoding.UTF8.GetBytes(value));
}
