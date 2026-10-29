/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.network

import android.net.Uri
import io.mockk.every
import io.mockk.mockk
import net.openid.appauth.AuthorizationServiceConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.ConscryptMode

@RunWith(RobolectricTestRunner::class)
@ConscryptMode(ConscryptMode.Mode.OFF)      // required because main project uses Conscrypt, but unit tests do not
class OAuthCustomTest {

    private val integration = mockk<OAuthIntegration> {
        every { redirectUri } returns Uri.parse("at.bitfire.davdroid:/oauth2/redirect")
    }
    private val config = AuthorizationServiceConfiguration(
        Uri.parse("https://sso.example/authorize"), Uri.parse("https://sso.example/token")
    )

    @Test
    fun `signIn builds a PKCE code request with the given client and scopes`() {
        val req = OAuthCustom(integration).signIn(config, "my-client", listOf("openid", "offline_access"))
        assertEquals("my-client", req.clientId)
        assertEquals("code", req.responseType)
        assertEquals("S256", req.codeVerifierChallengeMethod)
        assertTrue(req.codeVerifier!!.length >= 43)
        assertEquals("openid offline_access", req.scope)
        assertEquals("at.bitfire.davdroid:/oauth2/redirect", req.redirectUri.toString())
    }

    @Test
    fun `DEFAULT_SCOPES are the set proven against Stalwart`() {
        assertEquals(listOf("openid", "email", "profile", "offline_access"), OAuthCustom.DEFAULT_SCOPES)
    }
}
