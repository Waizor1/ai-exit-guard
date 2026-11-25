import unittest
from refresh_catalog import vetted


class RegistryPolicyTests(unittest.TestCase):
    def test_dedicated_public_and_publisher_verified(self):
        def check(url, publisher, expected, transport="streamable-http"):
            self.assertEqual(vetted({"url": url, "type": transport}, publisher),expected)
        check("https://mcp.linear.app/mcp","app.linear/linear","mcp.linear.app")
        check("https://radar.mcp.cloudflare.com/mcp","com.cloudflare.mcp/mcp","radar.mcp.cloudflare.com")
        check("https://mcp.context7.com/mcp","io.github.upstash/context7","mcp.context7.com")
        check("https://mcp.context7.com/mcp","io.github.random/unrelated",None)
        check("https://mcp.linear.app/mcp","app.linear-other/unrelated",None)
        check("https://api.githubcopilot.com/mcp","io.github.github/github-mcp-server",None)
        check("https://user@mcp.linear.app/mcp","app.linear/mcp",None)
        check("https://mcp.linear.app:8443/mcp","app.linear/mcp",None)
        check("https://mcp.linear.app/{token}","app.linear/mcp",None)
        check("https://*.mcp.linear.app/mcp","app.linear/mcp",None)
        check("https://mcp.example.com/mcp","com.example/mcp",None)
        check("https://foo.mcp.internal/mcp","internal.mcp/p",None)
        check("https://mcp.127-0-0-1.sslip.io/mcp","io.sslip/mcp",None)
        check("https://192.168.1.2/mcp","com.example/mcp",None)
        check("https://mcp.linear.app/mcp","app.linear/linear",None,transport="stdio")


if __name__=="__main__":
    unittest.main()
