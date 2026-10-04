package app.nivyx.android

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** UI-level smoke tests. Starting the VPN needs system consent, so that path is a manual device test. */
@RunWith(AndroidJUnit4::class)
class LaunchTest {
    @get:Rule val rule = createAndroidComposeRule<MainActivity>()

    @Test fun launchesInactiveWithStartButton() {
        rule.onNodeWithTag("protection_state").assertIsDisplayed()
        rule.onNodeWithText("Inactive").assertIsDisplayed()
        rule.onNodeWithTag("toggle").assertIsDisplayed()
    }

    @Test fun navigatesBetweenSections() {
        rule.onNodeWithTag("tab_Settings").performClick()
        rule.onAllNodesWithText("Settings").assertCountEquals(2) // tab label + screen title
        rule.onNodeWithTag("tab_About").performClick()
        rule.onNodeWithTag("check_updates").assertIsDisplayed()
        rule.onNodeWithTag("tab_Diagnostics").performClick()
        rule.onNodeWithTag("diag_host").assertIsDisplayed()
    }
}
