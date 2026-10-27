# SPDX-License-Identifier: Apache-2.0
# JNA reads the generated structures and callbacks by reflection.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class io.github.qorechain.qoresign.** { *; }
-dontwarn java.awt.**
