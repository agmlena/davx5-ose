package at.bitfire.davdroid.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class OAuthMetadataParserTest {

    private val stalwartMetadata = """
        {"resource":"https://mail.lena-oberrisser.eu/dav/cal/",
         "authorization_servers":["https://sso.lena-oberrisser.eu/application/o/stalwart-webui/"],
         "scopes_supported":["openid","offline_access","urn:ietf:params:oauth:scope:calendars"],
         "bearer_methods_supported":["header"]}
    """.trimIndent()

    @Test
    fun `resourceMetadataUrl reads Bearer challenge`() {
        val h = listOf("""Bearer realm="Stalwart Server", resource_metadata="https://mail.example/.well-known/oauth-protected-resource/dav/cal/"""")
        assertEquals("https://mail.example/.well-known/oauth-protected-resource/dav/cal/", OAuthMetadataParser.resourceMetadataUrl(h))
    }

    @Test
    fun `resourceMetadataUrl finds Bearer among several header values`() {
        val h = listOf(
            """Bearer realm="S", resource_metadata="https://a.example/m"""",
            """Basic realm="S""""
        )
        assertEquals("https://a.example/m", OAuthMetadataParser.resourceMetadataUrl(h))
    }

    @Test
    fun `resourceMetadataUrl finds Bearer when Basic comes first in one value`() {
        val h = listOf("""Basic realm="S", Bearer realm="S", resource_metadata="https://a.example/m"""")
        assertEquals("https://a.example/m", OAuthMetadataParser.resourceMetadataUrl(h))
    }

    @Test
    fun `resourceMetadataUrl ignores resource_metadata on a non-Bearer challenge`() {
        val h = listOf("""Basic realm="S", resource_metadata="https://evil.example/m"""")
        assertNull(OAuthMetadataParser.resourceMetadataUrl(h))
    }

    @Test
    fun `resourceMetadataUrl is null for Basic only`() {
        assertNull(OAuthMetadataParser.resourceMetadataUrl(listOf("""Basic realm="Stalwart Server"""")))
    }

    @Test
    fun `parseMetadata accepts trailing slash difference`() {
        val m = OAuthMetadataParser.parseMetadata(stalwartMetadata, "https://mail.lena-oberrisser.eu/dav/cal")
        assertEquals("https://sso.lena-oberrisser.eu/application/o/stalwart-webui/", m?.issuer)
        assertEquals(listOf("openid", "offline_access", "urn:ietf:params:oauth:scope:calendars"), m?.scopesSupported)
    }

    @Test
    fun `parseMetadata accepts a resource that is a prefix of the requested URL`() {
        val m = OAuthMetadataParser.parseMetadata(stalwartMetadata, "https://mail.lena-oberrisser.eu/dav/cal/user/default")
        assertEquals("https://sso.lena-oberrisser.eu/application/o/stalwart-webui/", m?.issuer)
    }

    @Test
    fun `parseMetadata rejects a resource on another host`() {
        val json = stalwartMetadata.replace("mail.lena-oberrisser.eu", "evil.example")
        assertNull(OAuthMetadataParser.parseMetadata(json, "https://mail.lena-oberrisser.eu/dav/cal/"))
    }

    @Test
    fun `parseMetadata rejects a sibling path that only shares a string prefix`() {
        assertNull(OAuthMetadataParser.parseMetadata(stalwartMetadata, "https://mail.lena-oberrisser.eu/dav/calendar-evil"))
    }

    @Test
    fun `parseMetadata rejects an http issuer`() {
        val json = stalwartMetadata.replace("https://sso.lena-oberrisser.eu", "http://sso.lena-oberrisser.eu")
        assertNull(OAuthMetadataParser.parseMetadata(json, "https://mail.lena-oberrisser.eu/dav/cal/"))
    }

    @Test
    fun `parseMetadata rejects non-JSON and empty server list`() {
        assertNull(OAuthMetadataParser.parseMetadata("<html>", "https://mail.lena-oberrisser.eu/dav/cal/"))
        assertNull(OAuthMetadataParser.parseMetadata("""{"resource":"https://mail.lena-oberrisser.eu/dav/cal/","authorization_servers":[]}""", "https://mail.lena-oberrisser.eu/dav/cal/"))
    }
}
