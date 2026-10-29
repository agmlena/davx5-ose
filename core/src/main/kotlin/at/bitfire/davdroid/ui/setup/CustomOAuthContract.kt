/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.ui.setup

import android.app.Activity
import android.content.Context
import android.content.Intent
import androidx.activity.result.contract.ActivityResultContract
import net.openid.appauth.AuthorizationException
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationResponse
import net.openid.appauth.AuthorizationService

sealed interface OAuthResult {
    data class Success(val response: AuthorizationResponse) : OAuthResult
    /** The user closed the browser or backed out. Not an error. */
    data object Cancelled : OAuthResult
    data class Failed(val exception: AuthorizationException?) : OAuthResult
}

/**
 * Like [at.bitfire.davdroid.network.OAuthIntegration.AuthorizationContract], but tells a user cancel apart
 * from a failure (that contract returns `null` for both).
 */
class CustomOAuthContract(
    private val authService: AuthorizationService
) : ActivityResultContract<AuthorizationRequest, OAuthResult>() {

    override fun createIntent(context: Context, input: AuthorizationRequest) =
        authService.getAuthorizationRequestIntent(input)

    override fun parseResult(resultCode: Int, intent: Intent?): OAuthResult {
        intent?.let { AuthorizationResponse.fromIntent(it) }?.let { return OAuthResult.Success(it) }

        val ex = intent?.let { AuthorizationException.fromIntent(it) }
        val userCancelled = ex != null &&
            ex.type == AuthorizationException.TYPE_GENERAL_ERROR &&
            ex.code == AuthorizationException.GeneralErrors.USER_CANCELED_AUTH_FLOW.code
        return when {
            userCancelled -> OAuthResult.Cancelled
            ex == null && resultCode == Activity.RESULT_CANCELED -> OAuthResult.Cancelled
            else -> OAuthResult.Failed(ex)
        }
    }
}
