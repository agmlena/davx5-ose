/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.ui.setup

import android.content.Context
import at.bitfire.davdroid.network.DiscoveryOutcome
import at.bitfire.davdroid.network.OAuthCustom
import at.bitfire.davdroid.network.OAuthDiscovery
import at.bitfire.davdroid.network.OAuthIntegration
import at.bitfire.davdroid.network.OAuthMetadata
import io.mockk.coEvery
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
import net.openid.appauth.AuthorizationService
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.logging.Logger

@OptIn(ExperimentalCoroutinesApi::class)
class CustomOAuthLoginViewModelTest {

    private val discovery = mockk<OAuthDiscovery>()
    private val custom = mockk<OAuthCustom>()
    private val context = mockk<Context>(relaxed = true) {
        every { getString(any()) } returns "error text"
    }

    @Before fun setUp() { Dispatchers.setMain(StandardTestDispatcher()) }
    @After fun tearDown() { Dispatchers.resetMain() }

    private fun vm() = CustomOAuthLoginViewModel(
        initialLoginInfo = LoginInfo(),
        authService = mockk(relaxed = true),
        context = context,
        logger = Logger.getAnonymousLogger(),
        discovery = discovery,
        oAuthCustom = custom,
        oAuthIntegration = mockk<OAuthIntegration>(relaxed = true)
    )

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
        val vm = vm()
        vm.setBaseUrl("mail.example"); vm.setClientId("c")
        vm.onAuthResult(OAuthResult.Cancelled)
        assertNull(vm.uiState.error)
        assertFalse(vm.uiState.busy)
        assertTrue(vm.uiState.canContinue)
    }

    @Test
    fun `a failed authorization shows an error`() = runTest {
        val vm = vm()
        vm.onAuthResult(OAuthResult.Failed(null))
        assertNotNull(vm.uiState.error)
    }

    @Test
    fun `manual issuer must be https`() = runTest {
        val vm = vm()
        vm.setBaseUrl("mail.example"); vm.setClientId("c")
        vm.showManualIssuer()
        vm.setIssuer("http://sso.example")
        vm.continueClicked()
        advanceUntilIdle()
        assertNull(vm.uiState.pendingRequest)
        assertNotNull(vm.uiState.error)
    }
}
