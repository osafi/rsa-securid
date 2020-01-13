#!/usr/bin/env ruby -w

require "openssl"

FLD_DIGIT_SHIFT = 6;
FLD_DIGIT_MASK = (0b111 << FLD_DIGIT_SHIFT);
FLD_NUMSECONDS_SHIFT = 0;
FLD_NUMSECONDS_MASK = (0b11 << FLD_NUMSECONDS_SHIFT);

class String
  def to_bcd
    [self].pack("H*").unpack("C*")
  end
end

class Token

  def initialize(serial:, seed:, pin: "00000000", flags: 17369)
    fail if serial !~ /^\d{12}$/
    fail if seed !~ /^(?:\h{2}:){15}\h{2}$/
    fail if pin !~ /^\d*$/

    @serial = serial.to_bcd
    @seed = seed.split(?:).map {|x| x.to_i(16) }.pack("C*")
    @pin = pin.chars.map(&:to_i)
    @flags = flags
  end

  def code(time=Time.now.utc)
    bcd_time = time.strftime("%Y%m%d%H#{time.min & minute_mask}0000").to_bcd

    key0 = encrypt(bcd_time[0...2], @seed)
    key1 = encrypt(bcd_time[0...3], key0)
    key0 = encrypt(bcd_time[0...4], key1)
    key1 = encrypt(bcd_time[0...5], key0)
    key0 = encrypt(bcd_time[0...8], key1)

    offset = if interval == 30
               # translated without testing, so this might be wrong...
               i = 0
               i |= 0b1000 if time.min.odd?
               i |= 0b0100 if time.min >= 30
               i
             else
               (time.min & 0b11) << 2
             end

    len = (@flags & FLD_DIGIT_MASK) >> FLD_DIGIT_SHIFT
    key0[offset, 4].unpack("N")[0]
      .digits.reverse[-len-1..]
      .zip(@pin)
      .map {|a,b| a + (b || 0) }
      .join
  end

  private

  def minute_mask
    (interval == 30) ? ~0b01 : ~0b11
  end

  def key_from_time(bcd_time_slice)
    key = Array.new(8, 0xAA)
    key[0...bcd_time_slice.length] = bcd_time_slice
    key[8..11] = @serial[2..5]
    key.fill(0xBB, 12..15)
    key.pack("C*")
  end

  def encrypt(input, key)
    cipher = OpenSSL::Cipher::AES128.new(:ECB)
    cipher.encrypt
    cipher.key = key
    data = key_from_time(input)
    (cipher.update(data) + cipher.final)[0..15]
  end

  def interval
    ((@flags & FLD_NUMSECONDS_MASK) >> FLD_NUMSECONDS_SHIFT).zero? ? 30 : 60
  end
end

if __FILE__ == $0
  token = Token.new(
    serial: ENV.fetch("RSA_AUTH_SERIAL"),
    seed: ENV.fetch("RSA_AUTH_SEED"),
  )

  puts token.code
end
