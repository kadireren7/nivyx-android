# JNI: the Rust library binds to these by name.
-keep class app.nivyx.android.core.NivyxNative { *; }
-keepclasseswithmembernames class * { native <methods>; }
# VpnService.protect(int) is invoked reflectively from Rust.
-keepclassmembers class * extends android.net.VpnService { public boolean protect(int); }
