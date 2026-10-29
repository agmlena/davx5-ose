/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.network

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OAuthDiscoveryTest {

    private val metadataJson = """{"resource":"https://mail.example/dav/cal/","authorization_servers":["https://sso.example/application/o/app/"],"scopes_supported":["openid"]}"""

    private fun discovery(handler: (String, String) -> Pair<HttpStatusCode, Pair<Map<String, List<String>>, String>>): OAuthDiscovery {
        val engine = MockEngine { request ->
            val (status, rest) = handler(request.method.value, request.url.toString())
            respond(rest.second, status, headersOf(*rest.first.map { it.key to it.value }.toTypedArray()))
        }
        return OAuthDiscovery { HttpClient(engine) { followRedirects = true } }
    }

    private val challenge = mapOf(HttpHeaders.WWWAuthenticate to listOf(
        """Bearer realm="S", resource_metadata="https://mail.example/.well-known/oauth-protected-resource/dav/cal/"""",
        """Basic realm="S""""
    ))

    @Test
    fun `discover follows a 401 challenge to the issuer`() = runTest {
        val d = discovery { method, url ->
            when {
                url == "https://mail.example/dav/cal/" && method == "PROPFIND" -> HttpStatusCode.Unauthorized to (challenge to "")
                url.startsWith("https://mail.example/.well-known/oauth-protected-resource") -> HttpStatusCode.OK to (emptyMap<String, List<String>>() to metadataJson)
                else -> HttpStatusCode.NotFound to (emptyMap<String, List<String>>() to "")
            }
        }
        val out = d.discover("https://mail.example/dav/cal/")
        assertTrue(out.toString(), out is DiscoveryOutcome.Found)
        assertEquals("https://sso.example/application/o/app/", (out as DiscoveryOutcome.Found).metadata.issuer)
    }

    @Test
    fun `discover fails cleanly when the server offers only Basic`() = runTest {
        val d = discovery { _, _ ->
            HttpStatusCode.Unauthorized to (mapOf(HttpHeaders.WWWAuthenticate to listOf("""Basic realm="S"""")) to "")
        }
        val out = d.discover("https://mail.example/dav/cal/")
        assertTrue(out.toString(), out is DiscoveryOutcome.Failed)
    }

    @Test
    fun `discover fails when the metadata resource belongs to another host`() = runTest {
        val d = discovery { _, url ->
            if (url.startsWith("https://mail.example/.well-known"))
                HttpStatusCode.OK to (emptyMap<String, List<String>>() to metadataJson.replace("mail.example", "evil.example"))
            else
                HttpStatusCode.Unauthorized to (challenge to "")
        }
        assertTrue(d.discover("https://mail.example/dav/cal/") is DiscoveryOutcome.Failed)
    }

    @Test
    fun `discover refuses a plain http challenge target`() = runTest {
        val d = discovery { _, _ -> HttpStatusCode.Unauthorized to (challenge to "") }
        assertTrue(d.discover("http://mail.example/dav/cal/") is DiscoveryOutcome.Failed)
    }

    @Test
    fun `normalizeBaseUrl adds https and rejects http`() {
        assertEquals("https://mail.example", OAuthDiscovery.normalizeBaseUrl("mail.example"))
        assertEquals("https://mail.example/dav/cal/", OAuthDiscovery.normalizeBaseUrl(" https://mail.example/dav/cal/ "))
        assertNull(OAuthDiscovery.normalizeBaseUrl("http://mail.example"))
        assertNull(OAuthDiscovery.normalizeBaseUrl(""))
    }
}
