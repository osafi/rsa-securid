package ms.safi.rsa.model;

import io.swagger.annotations.ApiModelProperty;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.Arrays;

public class Token {

    @ApiModelProperty(value = "RSA token serial number; 12 digits; additional info here", required = true)
    @NotNull(message = "Serial must be 12 digits")
    @Size(min = 12, max = 12)
    private String serial;

    @ApiModelProperty(value = "Decrypted device seed value in 16 octets (hex) separated by ':'", required = true)
    @NotNull(message = "Seed must be 16 octets separated by ':' (47 characters)")
    @Size(min = 47, max = 47)
    private String seedOctets;

    @ApiModelProperty("Token PIN number")
    private String pin;

    @ApiModelProperty("Internal flag used in token generation algorithm; " +
            "defaults to 17369 which is for tokens updating every 60 seconds")
    private int flags = 17369;

    @ApiModelProperty("Length of the returned token; defaults to 6")
    private int length = 6;

    public String getSerial() {
        return serial;
    }

    public void setSerial(String serial) {
        this.serial = serial;
    }

    public String getSeedOctets() {
        return seedOctets;
    }

    public void setSeedOctets(String seedOctets) {
        this.seedOctets = seedOctets;
    }

    public int[] getSeed() {
        return Arrays.stream(seedOctets.split(":"))
                     .map(h -> Integer.parseInt(h, 16))
                     .mapToInt(Integer::intValue)
                     .toArray();
    }

    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }

    public int getFlags() {
        return flags;
    }

    public void setFlags(int flags) {
        this.flags = flags;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public int getInterval() {
        int FLD_NUMSECONDS_SHIFT = 0;
        int FLD_NUMSECONDS_MASK = (0x03 << FLD_NUMSECONDS_SHIFT);

        if (((this.flags & FLD_NUMSECONDS_MASK) >> FLD_NUMSECONDS_SHIFT) == 0)
            return 30;
        else
            return 60;
    }

    @Override
    public String toString() {
        return "Token{" +
                "serial='" + serial + '\'' +
                ", seedOctets='" + seedOctets + '\'' +
                ", pin='" + pin + '\'' +
                ", flags=" + flags +
                ", length=" + length +
                '}';
    }
}
