/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.ui.setup

import android.content.ActivityNotFoundException
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import at.bitfire.davdroid.R

object CustomOAuthLogin : LoginType {

    override val title: Int
        get() = R.string.login_custom_oauth

    override val helpUrl: Uri?
        get() = null

    @Composable
    override fun LoginScreen(
        snackbarHostState: SnackbarHostState,
        initialLoginInfo: LoginInfo,
        onLogin: (LoginInfo) -> Unit
    ) {
        val model: CustomOAuthLoginViewModel = hiltViewModel(
            creationCallback = { factory: CustomOAuthLoginViewModel.Factory -> factory.create(loginInfo = initialLoginInfo) }
        )
        val uiState = model.uiState

        LaunchedEffect(uiState.result) {
            uiState.result?.let {
                onLogin(it)
                model.resetResult()
            }
        }

        val launcher = rememberLauncherForActivityResult(model.authorizationContract(), model::onAuthResult)
        LaunchedEffect(uiState.pendingRequest) {
            val request = uiState.pendingRequest ?: return@LaunchedEffect
            model.requestLaunched()
            try {
                launcher.launch(request)
            } catch (_: ActivityNotFoundException) {
                model.signInFailed()
            }
        }

        CustomOAuthLoginScreen(
            baseUrl = uiState.baseUrl, onSetBaseUrl = model::setBaseUrl,
            clientId = uiState.clientId, onSetClientId = model::setClientId,
            manualIssuer = uiState.manualIssuer,
            issuer = uiState.issuer, onSetIssuer = model::setIssuer,
            scopes = uiState.scopes, onSetScopes = model::setScopes,
            advertisedScopes = uiState.advertisedScopes,
            busy = uiState.busy, error = uiState.error,
            canContinue = uiState.canContinue,
            onContinue = model::continueClicked
        )
    }
}

@Composable
fun CustomOAuthLoginScreen(
    baseUrl: String, onSetBaseUrl: (String) -> Unit,
    clientId: String, onSetClientId: (String) -> Unit,
    manualIssuer: Boolean,
    issuer: String, onSetIssuer: (String) -> Unit,
    scopes: String, onSetScopes: (String) -> Unit,
    advertisedScopes: List<String>,
    busy: Boolean, error: String?,
    canContinue: Boolean,
    onContinue: () -> Unit
) {
    Column(
        Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        OutlinedTextField(
            value = baseUrl, onValueChange = onSetBaseUrl, singleLine = true, modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.login_custom_oauth_base_url)) },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri)
        )
        OutlinedTextField(
            value = clientId, onValueChange = onSetClientId, singleLine = true, modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.login_custom_oauth_client_id)) }
        )
        if (manualIssuer) {
            OutlinedTextField(
                value = issuer, onValueChange = onSetIssuer, singleLine = true, modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.login_custom_oauth_issuer)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri)
            )
        }
        OutlinedTextField(
            value = scopes, onValueChange = onSetScopes, modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.login_custom_oauth_scopes)) },
            supportingText = if (advertisedScopes.isNotEmpty()) {
                { Text(stringResource(R.string.login_custom_oauth_scopes_offered, advertisedScopes.joinToString(" "))) }
            } else null
        )
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Button(onClick = onContinue, enabled = canContinue, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.login_custom_oauth_sign_in))
        }
        if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
    }
}
