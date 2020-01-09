#!/usr/bin/env python3
import frida
import struct

session = frida.get_usb_device().attach("com.rsa.via")
script = session.create_script("""
Java.perform(function() {
    Java.use('com.rsa.securidlib.g.gg').$init.overload('[B').implementation = function(byteArr) {
        if (byteArr.length == 16) {
            send(byteArr);
        }
        return this.$init(byteArr);
    }
    Java.use('com.rsa.securidlib.android.AndroidSecurIDLib').getNextOtpWithDataProtection.implementation = function(str, byteArr, map) {
        console.log("Serial number: " + str);
        return this.getNextOtpWithDataProtection(str, byteArr, map);
    }
});
""")


def on_message(message, data):
    payload = message['payload']
    if len(payload) == 16:
        seed = struct.pack("16b", *payload)
        seedString = ":".join("{:02x}".format(c) for c in seed)
        print("Seed: " + seedString)


script.on('message', on_message)
script.load()

print("press enter to end")
input()
