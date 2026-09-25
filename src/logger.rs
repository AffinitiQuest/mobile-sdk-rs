/// Initiate the global logger for the mobile SDK.
///
/// This method should be called once per application lifecycle. The iOS branch below is what
/// makes any log::info!/log::warn! call in mobile-isomdl/mobile-sdk-rs visible on iOS at all -
/// previously this function only wired up a logger on Android (android_logger), so nothing using
/// the `log` crate ever reached Xcode's console or Console.app on iOS regardless of build type.
#[uniffi::export]
pub fn init_global_logger() {
    #[cfg(target_os = "android")]
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Trace)
            .with_tag("MOBILE_SDK_RS"),
    );

    #[cfg(target_os = "ios")]
    {
        // oslog's OsLogger forwards `log` crate calls to Apple's unified logging system
        // (os_log) - visible in Xcode's console when the process is attached, and in
        // Console.app (filter by subsystem "MOBILE_SDK_RS") for standalone/TestFlight builds.
        // `init()` errors only if a logger was already installed - ignored, since this
        // function is documented to be called once per app lifecycle and a repeat call
        // shouldn't panic.
        let _ = oslog::OsLogger::new("MOBILE_SDK_RS")
            .level_filter(log::LevelFilter::Trace)
            .init();
    }
}
