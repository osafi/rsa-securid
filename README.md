```sh
brew cask install android-platform-tools
adb devices
# allow usb debugging on the android device

cd android
./start-frida-server.sh
./capture-rsa-info.py

# run rsa authenticate and register the device
```
