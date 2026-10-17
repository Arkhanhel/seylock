# JNA binds the native functions by reflection: keep its classes and our
# binding interface with their names.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep interface io.github.arkhanhel.seylock.Ffi { *; }
-dontwarn java.awt.**
