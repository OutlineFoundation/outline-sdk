import android.os.Build
import fullstack_app.Fullstack_app.start

class AndroidPlatform : Platform {
    override val name: String = "Android ${Build.VERSION.SDK_INT}"
}

actual fun getPlatform(): Platform = AndroidPlatform()

actual fun startFullstackApp() {
    Thread(
        Runnable {
            fullstack_app.Fullstack_app.start()
        }
    ).start()
}