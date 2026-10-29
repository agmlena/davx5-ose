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
        val busy: Boolean = false,
        val error: String? = null,

        /** set when the browser should be opened; cleared by [requestLaunched] */
        val pendingRequest: AuthorizationRequest? = null,

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
        uiState = state.copy(busy = true, error = null, pendingRequest = null)
        viewModelScope.launch {
            try {
                val issuer = if (state.manualIssuer) {
                    state.issuer.trim().also {
                        if (!it.startsWith("https://")) {
                            uiState = uiState.copy(busy = false, error = "The issuer URL must start with https://")
                            return@launch
                        }
                    }
                } else when (val outcome = discovery.discover(state.baseUrl)) {
                    is DiscoveryOutcome.Found -> outcome.metadata.issuer
                    is DiscoveryOutcome.Failed -> {
                        uiState = uiState.copy(busy = false, manualIssuer = true, error = outcome.reason)
                        return@launch
                    }
                }

                val config = oAuthCustom.fetchConfiguration(issuer)
                // AppAuth sends no scope at all for an empty list, so fall back to the defaults
                val scopes = state.scopes.split(' ', '\n').filter { it.isNotBlank() }
                    .ifEmpty { OAuthCustom.DEFAULT_SCOPES }
                val request = oAuthCustom.signIn(config, state.clientId.trim(), scopes)
                uiState = uiState.copy(busy = false, pendingRequest = request)
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
        viewModelScope.launch {
            try {
                val authState = oAuthIntegration.authenticate(authService, authResponse)
                val baseUrl = requireNotNull(OAuthDiscovery.normalizeBaseUrl(uiState.baseUrl))
                uiState = uiState.copy(
                    result = LoginInfo(
                        baseUri = URI(baseUrl),
                        credentials = Credentials(authState = authState),
                        suggestedAccountName = URI(baseUrl).host
                    )
                )
            } catch (e: AuthorizationException) {
                logger.log(Level.WARNING, "OAuth code exchange failed", e)
                uiState = uiState.copy(error = e.errorDescription ?: e.error ?: context.getString(R.string.login_oauth_couldnt_obtain_auth_code))
            }
        }
    }

}
