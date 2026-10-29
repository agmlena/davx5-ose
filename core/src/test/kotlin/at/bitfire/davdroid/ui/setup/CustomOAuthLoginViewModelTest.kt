/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.ui.setup

import android.content.Context
import at.bitfire.davdroid.R
import at.bitfire.davdroid.network.DiscoveryOutcome
import at.bitfire.davdroid.network.OAuthCustom
import at.bitfire.davdroid.network.OAuthDiscovery
import at.bitfire.davdroid.network.OAuthIntegration
import at.bitfire.davdroid.network.OAuthMetadata
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.openid.appauth.AuthState
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.URI
import java.util.logging.Level
import java.util.logging.Logger

@OptIn(ExperimentalCoroutinesApi::class)
class CustomOAuthLoginViewModelTest {

    private val discovery = mockk<OAuthDiscovery>()
    private val custom = mockk<OAuthCustom>()
    private val integration = mockk<OAuthIntegration>(relaxed = true)
    private val context = mockk<Context>(relaxed = true) {
        every { getString(any()) } returns "error text"
        every { getString(R.string.login_custom_oauth_https_base_url) } returns HTTPS_BASE_URL_ERROR
        every { getString(R.string.login_custom_oauth_https_issuer) } returns HTTPS_ISSUER_ERROR
    }

    @Before fun setUp() { Dispatchers.setMain(StandardTestDispatcher()) }
    @After fun tearDown() { Dispatchers.resetMain() }

    private fun vm() = CustomOAuthLoginViewModel(
        initialLoginInfo = LoginInfo(),
        authService = mockk(relaxed = true),
        context = context,
        logger = Logger.getAnonymousLogger().apply { level = Level.OFF },     // expected failures would log stack traces
        discovery = discovery,
        oAuthCustom = custom,
        oAuthIntegration = integration
    )

    private fun stubFoundDiscovery(scopesSupported: List<String> = listOf("openid")) {
        coEvery { discovery.discover(any()) } returns DiscoveryOutcome.Found(OAuthMetadata(ISSUER, scopesSupported))
        coEvery { custom.fetchConfiguration(any()) } returns mockk(relaxed = true)
        every { custom.signIn(any(), any(), any()) } returns mockk(relaxed = true)
    }

    @Test
    fun `cannot continue with a blank client id`() {
        val vm = vm()
        vm.setBaseUrl("https://mail.example")
        vm.setClientId("   ")
        assertFalse(vm.uiState.canContinue)
        vm.setClientId("stalwart-webui")
        assertTrue(vm.uiState.canContinue)
    }

    @Test
    fun `failed discovery shows the manual issuer field with the reason`() = runTest {
        coEvery { discovery.discover(any()) } returns DiscoveryOutcome.Failed("no bearer challenge")
        val vm = vm()
        vm.setBaseUrl("mail.example"); vm.setClientId("c")
        vm.continueClicked()
        advanceUntilIdle()
        assertTrue(vm.uiState.manualIssuer)
        assertEquals("no bearer challenge", vm.uiState.error)
        assertNull(vm.uiState.pendingRequest)
    }

    @Test
    fun `successful discovery prepares an authorization request`() = runTest {
        coEvery { discovery.discover(any()) } returns DiscoveryOutcome.Found(OAuthMetadata("https://sso.example/o/app/", listOf("openid")))
        coEvery { custom.fetchConfiguration("https://sso.example/o/app/") } returns mockk(relaxed = true)
        every { custom.signIn(any(), "c", OAuthCustom.DEFAULT_SCOPES) } returns mockk(relaxed = true)
        val vm = vm()
        vm.setBaseUrl("mail.example"); vm.setClientId("c")
        vm.continueClicked()
        advanceUntilIdle()
        assertNotNull(vm.uiState.pendingRequest)
        assertFalse(vm.uiState.manualIssuer)
    }

    @Test
    fun `successful discovery shows the advertised scopes and requests the edited ones`() = runTest {
        stubFoundDiscovery(scopesSupported = listOf("openid", "urn:ietf:params:oauth:scope:mail"))
        val vm = vm()
        vm.setBaseUrl("mail.example"); vm.setClientId("c")
        vm.setScopes("openid email")
        vm.continueClicked()
        advanceUntilIdle()
        assertEquals(listOf("openid", "urn:ietf:params:oauth:scope:mail"), vm.uiState.advertisedScopes)
        verify { custom.signIn(any(), "c", listOf("openid", "email")) }
        assertNotNull(vm.uiState.pendingRequest)
    }

    @Test
    fun `blank scopes fall back to the default scopes`() = runTest {
        coEvery { discovery.discover(any()) } returns DiscoveryOutcome.Found(OAuthMetadata("https://sso.example/o/app/", listOf("openid")))
        coEvery { custom.fetchConfiguration("https://sso.example/o/app/") } returns mockk(relaxed = true)
        every { custom.signIn(any(), "c", any()) } returns mockk(relaxed = true)
        val vm = vm()
        vm.setBaseUrl("mail.example"); vm.setClientId("c")
        vm.setScopes("  \n ")
        vm.continueClicked()
        advanceUntilIdle()
        verify { custom.signIn(any(), "c", OAuthCustom.DEFAULT_SCOPES) }
        assertNotNull(vm.uiState.pendingRequest)
    }

    @Test
    fun `cancelling the browser shows no error and re-enables the form`() = runTest {
        coEvery { discovery.discover(any()) } returns DiscoveryOutcome.Failed("unused")
        val vm = vm()
        vm.setBaseUrl("mail.example"); vm.setClientId("c")
        vm.continueClicked()                // sets busy synchronously, before the coroutine runs
        assertTrue(vm.uiState.busy)
        vm.onAuthResult(OAuthResult.Cancelled)
        assertNull(vm.uiState.error)
        assertFalse(vm.uiState.busy)
        assertTrue(vm.uiState.canContinue)
        advanceUntilIdle()
    }

    @Test
    fun `a failed authorization shows an error`() = runTest {
        val vm = vm()
        vm.onAuthResult(OAuthResult.Failed(null))
        assertNotNull(vm.uiState.error)
    }

    @Test
    fun `manual issuer must be https`() = runTest {
        coEvery { custom.fetchConfiguration(any()) } returns mockk(relaxed = true)
        every { custom.signIn(any(), any(), any()) } returns mockk(relaxed = true)
        val vm = vm()
        vm.setBaseUrl("mail.example"); vm.setClientId("c")
        vm.showManualIssuer()
        vm.setIssuer("http://sso.example")
        vm.continueClicked()
        advanceUntilIdle()
        assertNull(vm.uiState.pendingRequest)
        assertEquals(HTTPS_ISSUER_ERROR, vm.uiState.error)
        assertFalse(vm.uiState.busy)
        coVerify(exactly = 0) { custom.fetchConfiguration(any()) }
    }

    @Test
    fun `manual issuer is accepted case-insensitively and trimmed`() = runTest {
        coEvery { custom.fetchConfiguration(any()) } returns mockk(relaxed = true)
        every { custom.signIn(any(), any(), any()) } returns mockk(relaxed = true)
        val vm = vm()
        vm.setBaseUrl("mail.example"); vm.setClientId("c")
        vm.showManualIssuer()
        vm.setIssuer("  HTTPS://sso.example ")
        vm.continueClicked()
        advanceUntilIdle()
        assertNull(vm.uiState.error)
        assertNotNull(vm.uiState.pendingRequest)
        coVerify { custom.fetchConfiguration("HTTPS://sso.example") }
    }

    @Test
    fun `http base url with a manual issuer is refused`() = runTest {
        coEvery { custom.fetchConfiguration(any()) } returns mockk(relaxed = true)
        every { custom.signIn(any(), any(), any()) } returns mockk(relaxed = true)
        val vm = vm()
        vm.setBaseUrl("http://mail.example"); vm.setClientId("c")
        vm.showManualIssuer()
        vm.setIssuer("https://sso.example")
        vm.continueClicked()
        advanceUntilIdle()
        assertEquals(HTTPS_BASE_URL_ERROR, vm.uiState.error)
        assertNull(vm.uiState.pendingRequest)
        assertFalse(vm.uiState.busy)
        coVerify(exactly = 0) { custom.fetchConfiguration(any()) }
    }

    @Test
    fun `blank base url is refused`() = runTest {
        stubFoundDiscovery()
        val vm = vm()
        vm.setBaseUrl("   "); vm.setClientId("c")
        vm.continueClicked()
        advanceUntilIdle()
        assertEquals(HTTPS_BASE_URL_ERROR, vm.uiState.error)
        assertNull(vm.uiState.pendingRequest)
        coVerify(exactly = 0) { discovery.discover(any()) }
        coVerify(exactly = 0) { custom.fetchConfiguration(any()) }
    }

    @Test
    fun `successful code exchange sets the result with the normalised base url`() = runTest {
        stubFoundDiscovery()
        val authState = mockk<AuthState>(relaxed = true)
        coEvery { integration.authenticate(any(), any()) } returns authState
        val vm = vm()
        vm.setBaseUrl("  mail.example/dav/ "); vm.setClientId("c")
        vm.continueClicked()
        advanceUntilIdle()
        vm.requestLaunched()
        vm.onAuthResult(OAuthResult.Success(mockk(relaxed = true)))
        assertTrue(vm.uiState.busy)         // a second tap cannot start a new authorization
        advanceUntilIdle()
        val result = requireNotNull(vm.uiState.result)
        assertEquals(URI("https://mail.example/dav/"), result.baseUri)
        assertEquals("mail.example", result.suggestedAccountName)
        assertEquals(authState, result.credentials?.authState)
        assertFalse(vm.uiState.busy)
        assertNull(vm.uiState.error)
    }

    @Test
    fun `a failing code exchange shows an error instead of crashing`() = runTest {
        stubFoundDiscovery()
        coEvery { integration.authenticate(any(), any()) } throws IllegalStateException("token endpoint broken")
        val vm = vm()
        vm.setBaseUrl("mail.example"); vm.setClientId("c")
        vm.continueClicked()
        advanceUntilIdle()
        vm.onAuthResult(OAuthResult.Success(mockk(relaxed = true)))
        advanceUntilIdle()
        assertNull(vm.uiState.result)
        assertEquals("token endpoint broken", vm.uiState.error)
        assertFalse(vm.uiState.busy)
    }

    companion object {
        const val ISSUER = "https://sso.example/o/app/"
        const val HTTPS_BASE_URL_ERROR = "base url must be https"
        const val HTTPS_ISSUER_ERROR = "issuer must be https"
    }
}
