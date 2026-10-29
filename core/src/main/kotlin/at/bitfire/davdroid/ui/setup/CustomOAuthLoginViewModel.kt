/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.ui.setup

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import at.bitfire.davdroid.R
import at.bitfire.davdroid.network.DiscoveryOutcome
import at.bitfire.davdroid.network.OAuthCustom
import at.bitfire.davdroid.network.OAuthDiscovery
import at.bitfire.davdroid.network.OAuthIntegration
import at.bitfire.davdroid.settings.Credentials
import dagger.assisted.Assisted
import dagger.assisted.AssistedFactory
import dagger.assisted.AssistedInject
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import net.openid.appauth.AuthorizationException
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationResponse
import net.openid.appauth.AuthorizationService
import java.net.URI
import java.util.logging.Level
import java.util.logging.Logger

@HiltViewModel(assistedFactory = CustomOAuthLoginViewModel.Factory::class)
class CustomOAuthLoginViewModel @AssistedInject constructor(
    @Assisted val initialLoginInfo: LoginInfo,
    private val authService: AuthorizationService,
    @ApplicationContext val context: Context,
    private val logger: Logger,
    private val discovery: OAuthDiscovery,
    private val oAuthCustom: OAuthCustom,
    private val oAuthIntegration: OAuthIntegration
) : ViewModel() {

    @AssistedFactory
    interface Factory {
        fun create(loginInfo: LoginInfo): CustomOAuthLoginViewModel
    }

    override fun onCleared() {
        authService.dispose()
    }


    data class UiState(
        val baseUrl: String = "",
        val clientId: String = "",
        val issuer: String = "",
        val scopes: String = OAuthCustom.DEFAULT_SCOPES.joinToString(" "),
        val manualIssuer: Boolean = false,
        /** `scopes_supported` from the discovered metadata, shown as a hint only */
        val advertisedScopes: List<String> = emptyList(),
        val busy: Boolean = false,
        val error: String? = null,

        /** set when the browser should be opened; cleared by [requestLaunched] */
        val pendingRequest: AuthorizationRequest? = null,
        /** https base URL the [pendingRequest] was prepared for; becomes the account's base URI */
        val normalizedBaseUrl: String? = null,

        /** login info (set after successful login) */
        val result: LoginInfo? = null
    ) {
        val canContinue = baseUrl.isNotBlank() && clientId.isNotBlank() && !busy
    }

    var uiState by mutableStateOf(UiState())
        private set

    init {
        uiState = uiState.copy(baseUrl = initialLoginInfo.baseUri?.toString() ?: "")
    }

    fun setBaseUrl(value: String) { uiState = uiState.copy(baseUrl = value) }
    fun setClientId(value: String) { uiState = uiState.copy(clientId = value) }
    fun setIssuer(value: String) { uiState = uiState.copy(issuer = value) }
    fun setScopes(value: String) { uiState = uiState.copy(scopes = value) }
    fun showManualIssuer() { uiState = uiState.copy(manualIssuer = true) }

    /** Starts discovery (or uses the manual issuer) and prepares the authorization request. */
    fun continueClicked() {
        val state = uiState
        uiState = state.copy(busy = true, error = null, pendingRequest = null, normalizedBaseUrl = null)
        viewModelScope.launch {
            try {
                // the base URL must be https on both paths: it receives the Bearer token later
                val baseUrl = OAuthDiscovery.normalizeBaseUrl(state.baseUrl)
                if (baseUrl == null) {
                    uiState = uiState.copy(busy = false, error = context.getString(R.string.login_custom_oauth_https_base_url))
                    return@launch
                }

                val issuer = if (state.manualIssuer) {
                    state.issuer.trim().also {
                        if (!it.startsWith("https://", ignoreCase = true)) {
                            uiState = uiState.copy(busy = false, error = context.getString(R.string.login_custom_oauth_https_issuer))
                            return@launch
                        }
                    }
                } else when (val outcome = discovery.discover(baseUrl)) {
                    is DiscoveryOutcome.Found -> {
                        uiState = uiState.copy(advertisedScopes = outcome.metadata.scopesSupported)
                        outcome.metadata.issuer
                    }
                    is DiscoveryOutcome.Failed -> {
                        uiState = uiState.copy(busy = false, manualIssuer = true, advertisedScopes = emptyList(), error = outcome.reason)
                        return@launch
                    }
                }

                val config = oAuthCustom.fetchConfiguration(issuer)
                // AppAuth sends no scope at all for an empty list, so fall back to the defaults
                val scopes = state.scopes.split(' ', '\n').filter { it.isNotBlank() }
                    .ifEmpty { OAuthCustom.DEFAULT_SCOPES }
                val request = oAuthCustom.signIn(config, state.clientId.trim(), scopes)
                uiState = uiState.copy(busy = false, pendingRequest = request, normalizedBaseUrl = baseUrl)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                logger.log(Level.WARNING, "Couldn't prepare OAuth login", e)
                uiState = uiState.copy(busy = false, manualIssuer = true, error = e.message ?: e.javaClass.simpleName)
            }
        }
    }

    fun requestLaunched() { uiState = uiState.copy(pendingRequest = null) }

    fun authorizationContract() = CustomOAuthContract(authService)

    fun onAuthResult(result: OAuthResult) {
        when (result) {
            is OAuthResult.Success -> authenticate(result.response)
            OAuthResult.Cancelled -> uiState = uiState.copy(busy = false)    // user backed out: no error
            is OAuthResult.Failed -> uiState = uiState.copy(
                busy = false,
                error = result.exception?.errorDescription ?: result.exception?.error
                    ?: context.getString(R.string.login_oauth_couldnt_obtain_auth_code)
            )
        }
    }

    /** Called after [UiState.result] was handed on, so going back to this screen does not log in again. */
    fun resetResult() {
        uiState = uiState.copy(result = null)
    }

    fun signInFailed() {
        uiState = uiState.copy(pendingRequest = null, error = context.getString(R.string.install_browser))
    }

    private fun authenticate(authResponse: AuthorizationResponse) {
        // busy during the code exchange, so a second tap cannot start a new authorization
        uiState = uiState.copy(busy = true, error = null)
        viewModelScope.launch {
            try {
                val authState = oAuthIntegration.authenticate(authService, authResponse)
                val baseUri = URI(checkNotNull(uiState.normalizedBaseUrl) { "No base URL for this authorization" })
                uiState = uiState.copy(
                    busy = false,
                    result = LoginInfo(
                        baseUri = baseUri,
                        credentials = Credentials(authState = authState),
                        suggestedAccountName = baseUri.host
                    )
                )
            } catch (e: CancellationException) {
                throw e
            } catch (e: AuthorizationException) {
                logger.log(Level.WARNING, "OAuth code exchange failed", e)
                uiState = uiState.copy(busy = false, error = e.errorDescription ?: e.error ?: context.getString(R.string.login_oauth_couldnt_obtain_auth_code))
            } catch (e: Exception) {
                logger.log(Level.WARNING, "OAuth login failed", e)
                uiState = uiState.copy(busy = false, error = e.message ?: e.javaClass.simpleName)
            }
        }
    }

}
