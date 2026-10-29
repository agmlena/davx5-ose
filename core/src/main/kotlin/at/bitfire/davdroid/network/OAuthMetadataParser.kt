/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.network

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

data class OAuthMetadata(
    val issuer: String,
    val scopesSupported: List<String>
)

/**
 * Parses RFC 9728 (OAuth protected resource metadata) discovery data.
 */
object OAuthMetadataParser {

    private val bearerStart = Regex("""(?i)(?:^|,\s*)Bearer(?:\s|$)""")
    private val nextScheme = Regex("""(?i),\s*(?:Basic|Digest|Negotiate|Mutual)\b""")
    private val resourceMetadata = Regex("""(?i)\bresource_metadata="([^"]+)"""")

    /**
     * Finds the `resource_metadata` parameter of the `Bearer` challenge.
     *
     * @param wwwAuthenticate all values of the `WWW-Authenticate` response header
     */
    fun resourceMetadataUrl(wwwAuthenticate: List<String>): String? {
        for (value in wwwAuthenticate) {
            val start = bearerStart.find(value) ?: continue
            var challenge = value.substring(start.range.last)
            nextScheme.find(challenge)?.let { challenge = challenge.substring(0, it.range.first) }
            resourceMetadata.find(challenge)?.let { return it.groupValues[1] }
        }
        return null
    }

    /**
     * Validates and reads a protected-resource metadata document.
     *
     * @param json          response body
     * @param requestedUrl  URL that was requested when the challenge was received; the
     *                      document's `resource` must be this URL or a path-prefix of it
     * @return issuer and scopes, or `null` when the document is unusable or fails validation
     */
    fun parseMetadata(json: String, requestedUrl: String): OAuthMetadata? {
        val obj = try {
            Json.parseToJsonElement(json).jsonObject
        } catch (_: Exception) {
            return null
        }

        val resource = (obj["resource"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
        if (!isPathPrefix(resource, requestedUrl))
            return null

        val issuer = ((obj["authorization_servers"] as? JsonArray)?.firstOrNull() as? JsonPrimitive)
            ?.takeIf { it.isString }?.content ?: return null
        if (!issuer.startsWith("https://"))
            return null

        val scopes = (obj["scopes_supported"] as? JsonArray)
            ?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
            .orEmpty()
        return OAuthMetadata(issuer, scopes)
    }

    private fun isPathPrefix(resource: String, requested: String): Boolean {
        val r = resource.trimEnd('/')
        val q = requested.trimEnd('/')
        return q == r || q.startsWith("$r/")
    }
}
