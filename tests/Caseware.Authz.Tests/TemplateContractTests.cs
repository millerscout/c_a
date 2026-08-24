namespace Caseware.Authz.Tests;

public sealed class TemplateContractTests
{
    [Fact]
    public void Http_api_authorizer_is_payload_2_simple_ttl_zero()
    {
        var yaml = File.ReadAllText(FindTemplate());
        Assert.Contains("AWS::Serverless::HttpApi", yaml, StringComparison.Ordinal);
        Assert.Contains("AuthorizerPayloadFormatVersion: \"2.0\"", yaml, StringComparison.Ordinal);
        Assert.Contains("EnableSimpleResponses: true", yaml, StringComparison.Ordinal);
        Assert.Contains("AuthorizerResultTtlInSeconds: 0", yaml, StringComparison.Ordinal);
        Assert.Contains("$request.header.Authorization", yaml, StringComparison.Ordinal);
    }

    [Fact]
    public void Lattice_and_cloud_map_integration_maps_identity_context()
    {
        var yaml = File.ReadAllText(FindTemplate());
        Assert.Contains("AWS::ServiceDiscovery::Service", yaml, StringComparison.Ordinal);
        Assert.Contains("AWS::VpcLattice::Service", yaml, StringComparison.Ordinal);
        Assert.Contains("overwrite:header.x-sub", yaml, StringComparison.Ordinal);
        Assert.Contains("$context.authorizer.sub", yaml, StringComparison.Ordinal);
        Assert.Contains("$context.authorizer.azp", yaml, StringComparison.Ordinal);
        Assert.Contains("$context.authorizer.roles", yaml, StringComparison.Ordinal);
        Assert.Contains("AuthorizationType: CUSTOM", yaml, StringComparison.Ordinal);
    }

    private static string FindTemplate()
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 8; i++)
        {
            var candidate = Path.Combine(dir, "infra", "template.yaml");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            dir = Directory.GetParent(dir)?.FullName ?? dir;
        }

        throw new FileNotFoundException("infra/template.yaml");
    }
}
