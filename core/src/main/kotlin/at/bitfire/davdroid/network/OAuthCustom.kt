/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.network

import androidx.core.net.toUri
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationServiceConfiguration
import net.openid.appauth.ResponseTypeValues
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
                    else -> cont.resumeWithException(ex ?: IllegalStateException("No configuration for $issuer"))
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

        /** Throws [IllegalStateException] unless the authorization and token endpoints are https. */
        internal fun requireHttpsEndpoints(config: AuthorizationServiceConfiguration) {
            for ((name, uri) in listOf("authorization" to config.authorizationEndpoint, "token" to config.tokenEndpoint))
                check(uri.scheme.equals("https", ignoreCase = true)) { "The $name endpoint is not https: $uri" }
        }

    }

}
