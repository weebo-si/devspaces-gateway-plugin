/*
 * Copyright (c) 2024-2026 Red Hat, Inc.
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *   Red Hat, Inc. - initial API and implementation
 */
package com.redhat.devtools.gateway.view.steps.auth

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.application.ModalityState
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.ui.JBColor
import com.intellij.ui.components.JBLabel
import com.intellij.ui.dsl.builder.Align
import com.intellij.ui.dsl.builder.panel
import java.awt.Cursor
import java.awt.Font
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.event.DocumentListener
import java.awt.event.KeyListener
import com.redhat.devtools.gateway.DevSpacesBundle
import com.redhat.devtools.gateway.view.ui.PasteClipboardMenu
import com.redhat.devtools.gateway.view.ui.PasswordFieldWithToggle
import com.redhat.devtools.gateway.DevSpacesContext
import com.redhat.devtools.gateway.auth.tls.TlsContext
import com.redhat.devtools.gateway.kubeconfig.KubeConfigUtils
import com.redhat.devtools.gateway.openshift.Cluster
import com.redhat.devtools.gateway.util.ClipboardTokenMonitor
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JPanel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext

/**
 * Authentication strategy for token-based authentication.
 */
class TokenAuthenticationStrategy(
    tfServer: Any,
    saveKubeconfig: suspend (Cluster, String, ProgressIndicator) -> Unit,
    private val onFieldChanged: () -> DocumentListener,
    private val createEnterKeyListener: () -> KeyListener
) : AbstractAuthenticationStrategy(
    tfServer,
    saveKubeconfig
) {

    private val tokenFieldWithToggle = PasswordFieldWithToggle().apply {
        setToggleButtonTooltip(DevSpacesBundle.message("connector.wizard_step.openshift_connection.checkbox.show_token"))
        passwordField.document.addDocumentListener(onFieldChanged())
        PasteClipboardMenu.addTo(passwordField)
        passwordField.addKeyListener(createEnterKeyListener())
    }

    val tfToken = tokenFieldWithToggle.passwordField

    val tokenSuggestionLabel = JBLabel().apply {
        text = ""
        foreground = JBColor.BLUE
        cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
        isVisible = false
        font = font.deriveFont(Font.ITALIC or Font.PLAIN)
    }

    private val clipboardMonitor = ClipboardTokenMonitor()
    private var lastDetectedToken: String? = null
    private var tokenLabelListener: MouseAdapter? = null

    override fun getAuthMethod(): AuthMethod = AuthMethod.TOKEN

    override fun getTabTitle(): String =
        DevSpacesBundle.message("connector.wizard_step.openshift_connection.tab.token")

    override fun createPanel(): JPanel = panel {
        row {
            cell(tokenSuggestionLabel).align(Align.FILL)
        }
        row(DevSpacesBundle.message("connector.wizard_step.openshift_connection.label.token")) {
            cell(tokenFieldWithToggle).resizableColumn().align(Align.FILL)
        }
    }

    override suspend fun authenticate(
        selectedCluster: Cluster,
        server: String,
        tlsContext: TlsContext,
        devSpacesContext: DevSpacesContext,
        indicator: ProgressIndicator
    ) {
        val typedToken = String(tfToken.password)
        val exec = selectedCluster.exec.takeIf { typedToken.isEmpty() }
        val token = if (exec != null) {
            indicator.text = "Getting a token from ${exec["command"]} (kubeconfig exec plugin)..."
            getExecToken(exec, indicator)
        } else {
            typedToken
        }

        indicator.text = "Validating token..."

        val client = createValidatedApiClient(
            server,
            token,
            tlsContext = tlsContext,
            errorMessage = "Authentication failed: invalid server URL or token."
        )

        // A token from the exec plugin expires: saving it next to the exec entry would break other tools
        if (exec == null) {
            saveKubeconfig.invoke(selectedCluster, token, indicator)
        }
        devSpacesContext.client = client
    }

    /**
     * Shows the login URL that the plugin prints (e.g. `kubectl oidc-login` when it cannot open a browser).
     */
    private suspend fun getExecToken(exec: Map<*, *>, indicator: ProgressIndicator): String = withContext(Dispatchers.IO) {
        try {
            runInterruptible {
                KubeConfigUtils.getExecToken(exec) { line ->
                    URL_PATTERN.find(line)?.let { indicator.text2 = "Log in at ${it.value}" }
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw AuthenticationException("The kubeconfig exec plugin failed: ${e.message}", e)
        } finally {
            indicator.text2 = null
        }
    }

    private companion object {
        val URL_PATTERN = Regex("https?://\\S+")
    }

    /** Without a token, the kubeconfig exec plugin of the selected cluster (e.g. `kubectl oidc-login`) provides one */
    override fun isNextEnabled(): Boolean =
        isServerSelected()
                && (tfToken.password?.isNotEmpty() == true || selectedClusterHasExec())

    private fun selectedClusterHasExec(): Boolean =
        ((tfServer as? JComboBox<*>)?.editor?.item as? Cluster)?.exec != null

    /**
     * Dirty vs kubeconfig only once the token field has content; an empty field after switching tabs is not dirty.
     */
    override fun isDirty(saved: Cluster): Boolean {
        val cur = tfToken.password ?: CharArray(0)
        if (cur.isEmpty()) return false
        return tokenDiffers(saved.token, cur)
    }

    private fun tokenDiffers(savedToken: String?, current: CharArray = CharArray(0)): Boolean {
        val saved = savedToken.orEmpty()
        val savedBlank = saved.isBlank()
        val curEmpty = current.isEmpty()
        if (savedBlank && curEmpty) return false
        if (savedBlank != curEmpty) return true
        return !saved.toCharArray().contentEquals(current)
    }

    /**
     * Start monitoring clipboard for tokens.
     * Should be called during initialization.
     */
    fun startMonitoring(parentComponent: JComponent) {
        clipboardMonitor.addListener { token ->
            lastDetectedToken = token
            ApplicationManager.getApplication().invokeLater(
                {
                    tokenSuggestionLabel.apply {
                        text = "Token detected in clipboard. Click here to use it."
                        isVisible = true
                        isEnabled = true
                    }
                },
                ModalityState.stateForComponent(parentComponent)
            )
        }

        tokenLabelListener = object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent?) {
                val token = lastDetectedToken ?: return
                tfToken.text = token
                tokenSuggestionLabel.isVisible = false
            }
        }
        tokenSuggestionLabel.addMouseListener(tokenLabelListener)
        tokenSuggestionLabel.isVisible = false

        clipboardMonitor.start()
        clipboardMonitor.checkNow()?.let { token ->
            lastDetectedToken = token
            tokenSuggestionLabel.apply {
                text = "Token detected in clipboard. Click here to use it."
                isVisible = true
                isEnabled = true
            }
        }
    }

    /**
     * Stop monitoring clipboard and clean up resources.
     * Should be called during disposal.
     */
    fun stopMonitoring() {
        tokenLabelListener?.let { listener ->
            tokenSuggestionLabel.removeMouseListener(listener)
        }
        clipboardMonitor.stop()
    }
}
