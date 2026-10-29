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

    private val requests = mutableListOf<String>()

    private fun discovery(handler: (String, String) -> Pair<HttpStatusCode, Pair<Map<String, List<String>>, String>>): OAuthDiscovery {
        val engine = MockEngine { request ->
            requests += request.method.value + " " + request.url.toString()
            val (status, rest) = handler(request.method.value, request.url.toString())
            respond(rest.second, status, headersOf(*rest.first.map { it.key to it.value }.toTypedArray()))
        }
        return OAuthDiscovery { HttpClient(engine) { followRedirects = false } }
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
    fun `discover refuses a plain http base url without any request`() = runTest {
        val d = discovery { _, _ -> HttpStatusCode.Unauthorized to (challenge to "") }
        assertTrue(d.discover("http://mail.example/dav/cal/") is DiscoveryOutcome.Failed)
        assertTrue(requests.toString(), requests.isEmpty())
    }

    private val none = emptyMap<String, List<String>>()
    private fun redirect(location: String) = HttpStatusCode.TemporaryRedirect to (mapOf(HttpHeaders.Location to listOf(location)) to "")

    @Test
    fun `discover follows a PROPFIND redirect manually from well-known`() = runTest {
        val d = discovery { method, url ->
            when {
                url == "https://mail.example/.well-known/caldav" -> redirect("https://mail.example/dav/cal")
                url == "https://mail.example/dav/cal" && method == "PROPFIND" -> HttpStatusCode.Unauthorized to (challenge to "")
                url.startsWith("https://mail.example/.well-known/oauth-protected-resource") -> HttpStatusCode.OK to (none to metadataJson)
                else -> HttpStatusCode.NotFound to (none to "")
            }
        }
        val out = d.discover("mail.example")
        assertTrue(out.toString(), out is DiscoveryOutcome.Found)
    }

    @Test
    fun `discover fails on a redirect to plain http`() = runTest {
        val d = discovery { _, _ -> redirect("http://mail.example/dav/cal") }
        assertTrue(d.discover("https://mail.example") is DiscoveryOutcome.Failed)
        assertTrue(requests.toString(), requests.none { it.contains("http://") })
    }

    @Test
    fun `discover fails on a redirect loop`() = runTest {
        val d = discovery { _, _ -> redirect("https://mail.example/loop") }
        assertTrue(d.discover("https://mail.example/loop") is DiscoveryOutcome.Failed)
        assertEquals(6, requests.size)
    }

    @Test
    fun `discover falls through from caldav to carddav to the bare url`() = runTest {
        val d = discovery { _, _ -> HttpStatusCode.NotFound to (none to "") }
        assertTrue(d.discover("https://mail.example") is DiscoveryOutcome.Failed)
        assertEquals(listOf(
            "PROPFIND https://mail.example/.well-known/caldav",
            "PROPFIND https://mail.example/.well-known/carddav",
            "PROPFIND https://mail.example"
        ), requests)
    }

    @Test
    fun `discover finds the challenge on the bare url after both well-known paths fail`() = runTest {
        val rootChallenge = mapOf(HttpHeaders.WWWAuthenticate to listOf(
            """Bearer resource_metadata="https://mail.example/.well-known/oauth-protected-resource""""))
        val rootMetadata = metadataJson.replace("https://mail.example/dav/cal/", "https://mail.example/")
        val d = discovery { method, url ->
            when {
                url == "https://mail.example" && method == "PROPFIND" -> HttpStatusCode.Unauthorized to (rootChallenge to "")
                url == "https://mail.example/.well-known/oauth-protected-resource" -> HttpStatusCode.OK to (none to rootMetadata)
                else -> HttpStatusCode.NotFound to (none to "")
            }
        }
        val out = d.discover("https://mail.example")
        assertTrue(out.toString(), out is DiscoveryOutcome.Found)
        assertEquals(listOf(
            "PROPFIND https://mail.example/.well-known/caldav",
            "PROPFIND https://mail.example/.well-known/carddav",
            "PROPFIND https://mail.example",
            "GET https://mail.example/.well-known/oauth-protected-resource"
        ), requests)
    }

    @Test
    fun `discover follows a 303 redirect`() = runTest {
        val d = discovery { method, url ->
            when {
                url == "https://mail.example/dav/" -> HttpStatusCode.SeeOther to (mapOf(HttpHeaders.Location to listOf("https://mail.example/dav/cal/")) to "")
                url == "https://mail.example/dav/cal/" && method == "PROPFIND" -> HttpStatusCode.Unauthorized to (challenge to "")
                url.startsWith("https://mail.example/.well-known/oauth-protected-resource") -> HttpStatusCode.OK to (none to metadataJson)
                else -> HttpStatusCode.NotFound to (none to "")
            }
        }
        val out = d.discover("https://mail.example/dav/")
        assertTrue(out.toString(), out is DiscoveryOutcome.Found)
        assertEquals("PROPFIND https://mail.example/dav/cal/", requests[1])
    }

    @Test
    fun `discover follows a relative Location like the live server`() = runTest {
        val liveChallenge = mapOf(HttpHeaders.WWWAuthenticate to listOf(
            """Bearer resource_metadata="https://mail.example/.well-known/oauth-protected-resource/dav/cal""""))
        val liveMetadata = metadataJson.replace("https://mail.example/dav/cal/", "https://mail.example/dav/cal")
        val d = discovery { method, url ->
            when {
                url == "https://mail.example/.well-known/caldav" && method == "PROPFIND" -> redirect("/dav/cal")
                url == "https://mail.example/dav/cal" && method == "PROPFIND" -> HttpStatusCode.Unauthorized to (liveChallenge to "")
                url == "https://mail.example/.well-known/oauth-protected-resource/dav/cal" -> HttpStatusCode.OK to (none to liveMetadata)
                else -> HttpStatusCode.NotFound to (none to "")
            }
        }
        val out = d.discover("mail.example")
        assertTrue(out.toString(), out is DiscoveryOutcome.Found)
        assertEquals("https://sso.example/application/o/app/", (out as DiscoveryOutcome.Found).metadata.issuer)
        assertEquals(listOf(
            "PROPFIND https://mail.example/.well-known/caldav",
            "PROPFIND https://mail.example/dav/cal",
            "GET https://mail.example/.well-known/oauth-protected-resource/dav/cal"
        ), requests)
    }

    @Test
    fun `discover probes only the given url when it has a path`() = runTest {
        val d = discovery { _, _ -> HttpStatusCode.NotFound to (none to "") }
        d.discover("https://mail.example/dav/cal/")
        assertEquals(listOf("PROPFIND https://mail.example/dav/cal/"), requests)
    }

    @Test
    fun `discover returns Failed for a malformed address`() = runTest {
        val d = discovery { _, _ -> HttpStatusCode.NotFound to (none to "") }
        assertTrue(d.discover("mail example") is DiscoveryOutcome.Failed)
        assertTrue(requests.isEmpty())
    }

    @Test
    fun `discover adds https to a scheme-less host`() = runTest {
        val d = discovery { _, _ -> HttpStatusCode.NotFound to (none to "") }
        d.discover("mail.example")
        assertTrue(requests.toString(), requests.first().startsWith("PROPFIND https://"))
    }

    @Test
    fun `discover fails when resource_metadata is not https`() = runTest {
        val d = discovery { _, _ ->
            HttpStatusCode.Unauthorized to (mapOf(HttpHeaders.WWWAuthenticate to listOf(
                """Bearer resource_metadata="http://mail.example/.well-known/oauth-protected-resource"""")) to "")
        }
        assertTrue(d.discover("https://mail.example/dav/cal/") is DiscoveryOutcome.Failed)
        assertEquals(1, requests.size)
    }

    @Test
    fun `normalizeBaseUrl adds https and rejects http`() {
        assertEquals("https://mail.example", OAuthDiscovery.normalizeBaseUrl("mail.example"))
        assertEquals("https://mail.example/dav/cal/", OAuthDiscovery.normalizeBaseUrl(" https://mail.example/dav/cal/ "))
        assertNull(OAuthDiscovery.normalizeBaseUrl("http://mail.example"))
        assertNull(OAuthDiscovery.normalizeBaseUrl(""))
    }
}
