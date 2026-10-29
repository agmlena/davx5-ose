/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.network

import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.request.url
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.CancellationException
import java.net.URI
import java.net.URISyntaxException
import java.util.logging.Level
import java.util.logging.Logger
import javax.inject.Inject
import javax.inject.Provider

sealed interface DiscoveryOutcome {
    data class Found(val metadata: OAuthMetadata) : DiscoveryOutcome
    data class Failed(val reason: String) : DiscoveryOutcome
}

/**
 * Finds the OAuth issuer of a CalDAV/CardDAV server using RFC 9728: an unauthenticated
 * request gets a 401 with `WWW-Authenticate: Bearer resource_metadata="…"`.
 */
class OAuthDiscovery(
    private val newClient: () -> HttpClient
) {

    @Inject
    constructor(builder: Provider<HttpClientBuilder>) : this({ builder.get().build() })

    private val logger: Logger = Logger.getLogger(javaClass.name)

    suspend fun discover(baseUrl: String): DiscoveryOutcome {
        val normalized = normalizeBaseUrl(baseUrl) ?: return DiscoveryOutcome.Failed("The server address must be an https:// URL")

        val path = try {
            URI(normalized).path
        } catch (e: URISyntaxException) {
            return DiscoveryOutcome.Failed("The server address is not a valid URL")
        }
        val candidates = if (path.isNullOrEmpty() || path == "/")
            listOf(normalized.trimEnd('/') + "/.well-known/caldav", normalized.trimEnd('/') + "/.well-known/carddav")
        else
            listOf(normalized)

        var lastReason = "The server did not answer"
        newClient().use { client ->
            for (candidate in candidates) {
                try {
                    var currentUrl = candidate
                    var hops = 0
                    var response = propfind(client, currentUrl)
                    while (response.status.value in REDIRECT_CODES) {
                        val location = response.headers[HttpHeaders.Location]
                        if (location == null) break
                        if (++hops > MAX_REDIRECTS) {
                            lastReason = "Too many redirects"
                            break
                        }
                        val target = try {
                            URI(currentUrl).resolve(location).toString()
                        } catch (e: IllegalArgumentException) {
                            null
                        }
                        if (target == null || !target.startsWith("https://", ignoreCase = true)) {
                            lastReason = "The server redirected to a non-https or invalid address"
                            hops = -1
                            break
                        }
                        currentUrl = target
                        response = propfind(client, currentUrl)
                    }
                    if (hops > MAX_REDIRECTS || hops == -1) continue
                    if (response.status != HttpStatusCode.Unauthorized) {
                        lastReason = "The server did not ask for authentication (HTTP ${response.status.value})"
                        continue
                    }
                    val finalUrl = currentUrl
                    val metadataUrl = OAuthMetadataParser.resourceMetadataUrl(response.headers.getAll(HttpHeaders.WWWAuthenticate).orEmpty())
                    if (metadataUrl == null) {
                        lastReason = "The server does not offer OAuth (no Bearer challenge with resource_metadata)"
                        continue
                    }
                    if (!metadataUrl.startsWith("https://")) {
                        lastReason = "The OAuth metadata URL is not https"
                        continue
                    }
                    val metadataResponse = client.request { url(metadataUrl) }
                    if (metadataResponse.status != HttpStatusCode.OK) {
                        lastReason = "The OAuth metadata could not be fetched (HTTP ${metadataResponse.status.value})"
                        continue
                    }
                    val metadata = OAuthMetadataParser.parseMetadata(metadataResponse.bodyAsText(), finalUrl)
                    if (metadata == null) {
                        lastReason = "The OAuth metadata is invalid or does not belong to this server"
                        continue
                    }
                    return DiscoveryOutcome.Found(metadata)
                } catch (e: Exception) {
                    if (e is CancellationException) throw e
                    logger.log(Level.INFO, "OAuth discovery request failed", e)
                    lastReason = "Could not connect: ${e.message}"
                }
            }
        }
        return DiscoveryOutcome.Failed(lastReason)
    }

    private suspend fun propfind(client: HttpClient, url: String) = client.request {
        url(url)
        method = HttpMethod("PROPFIND")
        header("Depth", "0")
    }

    companion object {

        private val REDIRECT_CODES = setOf(301, 302, 307, 308)
        private const val MAX_REDIRECTS = 5

        /** Adds `https://` when no scheme is given; returns `null` for blank input or plain http. */
        fun normalizeBaseUrl(input: String): String? {
            val s = input.trim()
            if (s.isEmpty()) return null
            if (s.startsWith("http://", ignoreCase = true)) return null
            return if (s.startsWith("https://", ignoreCase = true)) s else "https://$s"
        }
    }
}
