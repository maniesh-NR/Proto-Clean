# Keep the WireGuard tunnel library (JNI + reflection on config classes)
-keep class com.wireguard.** { *; }
-keep class com.wireguard.android.** { *; }
-dontwarn com.wireguard.**

# OkHttp / Conscrypt
-dontwarn okhttp3.**
-dontwarn org.conscrypt.**
