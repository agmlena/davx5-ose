/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.ui.setup

import android.app.Activity
import android.content.Intent
import io.mockk.mockk
import net.openid.appauth.AuthorizationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.ConscryptMode

@RunWith(RobolectricTestRunner::class)
@ConscryptMode(ConscryptMode.Mode.OFF)      // required because main project uses Conscrypt, but unit tests do not
class CustomOAuthContractTest {

    private val contract = CustomOAuthContract(mockk(relaxed = true))

    @Test
    fun `user cancelled exception is Cancelled`() {
        val intent = AuthorizationException.GeneralErrors.USER_CANCELED_AUTH_FLOW.toIntent()
        assertEquals(OAuthResult.Cancelled, contract.parseResult(Activity.RESULT_CANCELED, intent))
    }

    @Test
    fun `result canceled without data is Cancelled`() {
        assertEquals(OAuthResult.Cancelled, contract.parseResult(Activity.RESULT_CANCELED, null))
    }

    @Test
    fun `a server error is Failed, not Cancelled`() {
        val intent = AuthorizationException.AuthorizationRequestErrors.ACCESS_DENIED.toIntent()
        val result = contract.parseResult(Activity.RESULT_CANCELED, intent)
        assertTrue(result.toString(), result is OAuthResult.Failed)
    }

    @Test
    fun `an intent without response or error is Failed`() {
        assertTrue(contract.parseResult(Activity.RESULT_OK, Intent()) is OAuthResult.Failed)
    }
}
