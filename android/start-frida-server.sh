#!/bin/sh

adb push frida-server-12.8.6-android-arm64 /data/local/tmp/frida
adb shell "chmod 755 /data/local/tmp/frida"
adb shell "su -c '/data/local/tmp/frida'"
