import fullstack_app.Fullstack_app.start

class JVMPlatform: Platform {
    override val name: String = "Java ${System.getProperty("java.version")}"
}

actual fun getPlatform(): Platform = JVMPlatform()

actual fun startFullstackApp() {
    Thread(
        Runnable {
            fullstack_app.Fullstack_app.start()
        }
    ).start()
}