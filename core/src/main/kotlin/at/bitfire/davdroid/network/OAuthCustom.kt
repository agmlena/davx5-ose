/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.network

import androidx.core.net.toUri
import net.openid.appauth.AuthorizationException
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationServiceConfiguration
import net.openid.appauth.ResponseTypeValues
import java.io.FileNotFoundException
import javax.inject.Inject
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

/**
 * OAuth for a user-supplied issuer and client ID (as opposed to [OAuthFastmail] / [OAuthGoogle]).
 */
class OAuthCustom @Inject constructor(
    private val oAuthIntegration: OAuthIntegration
) {

    /** Reads the OIDC discovery document of [issuer] and returns the endpoints (which must be https). */
    suspend fun fetchConfiguration(issuer: String): AuthorizationServiceConfiguration =
        suspendCoroutine<AuthorizationServiceConfiguration> { cont ->
            AuthorizationServiceConfiguration.fetchFromIssuer(issuer.toUri()) { config, ex ->
                when {
                    config != null -> cont.resume(config)
                    else -> cont.resumeWithException(describeFailure(issuer, ex))
                }
            }
        }.also { requireHttpsEndpoints(it) }

    /** Builds an authorization-code request with PKCE (AppAuth generates the S256 verifier). */
    fun signIn(config: AuthorizationServiceConfiguration, clientId: String, scopes: List<String>): AuthorizationRequest =
        AuthorizationRequest.Builder(
            config,
            clientId,
            ResponseTypeValues.CODE,
            oAuthIntegration.redirectUri
        )
            .setScopes(scopes)
            .build()


    companion object {

        /** Scopes that Stalwart accepted in a live test against Authentik (2026-10-29). */
        val DEFAULT_SCOPES = listOf("openid", "email", "profile", "offline_access")

        /**
         * AppAuth reports every failed discovery request as just "Network error". Names the real cause
         * (missing document, unreachable host, unusable document) so the user can tell which part to fix.
         */
        internal fun describeFailure(issuer: String, ex: AuthorizationException?): Exception {
            if (ex == null)
                return IllegalStateException("No configuration for $issuer")
            val reason = when {
                ex == AuthorizationException.GeneralErrors.INVALID_DISCOVERY_DOCUMENT ||
                ex == AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR ||
                ex.type == AuthorizationException.TYPE_GENERAL_ERROR && ex.code == AuthorizationException.GeneralErrors.INVALID_DISCOVERY_DOCUMENT.code ->
                    "the OpenID configuration at $issuer is not valid"
                ex.cause is FileNotFoundException ->
                    "no OpenID configuration found at $issuer (HTTP 404)"
                ex.cause != null ->
                    "$issuer could not be read (${ex.cause?.message ?: ex.cause?.javaClass?.simpleName})"
                else -> ex.message ?: ex.error ?: ex.javaClass.simpleName
            }
            return IllegalStateException(reason, ex)
        }

        /** Throws [IllegalStateException] unless the authorization and token endpoints are https. */
        internal fun requireHttpsEndpoints(config: AuthorizationServiceConfiguration) {
            for ((name, uri) in listOf("authorization" to config.authorizationEndpoint, "token" to config.tokenEndpoint))
                check(uri.scheme.equals("https", ignoreCase = true)) { "The $name endpoint is not https: $uri" }
        }

    }

}
