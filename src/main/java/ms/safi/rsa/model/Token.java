package ms.safi.rsa.model;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.Arrays;

public class Token {

    @NotNull(message = "Serial must be 12 characters")
    @Size(min = 12, max = 12)
    private String serial;
    @NotNull
    private int[] seed;
    private String pin;
    private int flags = 17369;
    private int length = 6;

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public String getSerial() {
        return serial;
    }

    public void setSerial(String serial) {
        this.serial = serial;
    }

    public int[] getSeed() {
        return seed;
    }

    public void setSeed(String seed) {
        this.seed = Arrays.stream(seed.split(":"))
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
                ", seed=" + Arrays.toString(seed) +
                ", pin='" + pin + '\'' +
                ", flags=" + flags +
                ", length=" + length +
                '}';
    }
}
