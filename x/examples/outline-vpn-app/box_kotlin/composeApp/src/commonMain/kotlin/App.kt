import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import org.jetbrains.compose.ui.tooling.preview.Preview

import com.multiplatform.webview.web.WebView
import com.multiplatform.webview.web.rememberWebViewState

@Composable
@Preview
fun App() {
    startFullstackApp()

    val state = rememberWebViewState("http://localhost:8080");

    WebView(state, modifier = Modifier.fillMaxWidth().fillMaxHeight())
}