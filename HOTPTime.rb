# TOTP TimeBase OTP Client ツール
# TOTP: Time-Based One-Time Password Algorithm（RFC6283）を Ruby で実装
# http://tools.ietf.org/html/rfc6238
# 　token.cfg ファイルからの入力項目を HOTP TimeBase で OTP 変換
#   入力項目　TokenID，SharedSecret
#   出力項目　TokenID，OTP
#

require 'base64'
require 'openssl'

class OtpAlgorithm
  def initialize(sec, mf, codedigit)
    @sec = sec
    @mf = mf
    @codedigit = codedigit
  end
  def generate_otp
    hash = OpenSSL::HMAC::digest(OpenSSL::Digest::SHA1.new, @sec, @mf)
    offset = hash[hash.length-1] & 0xf
    binary = ((hash[offset] & 0x7f)<<24) |
    ((hash[offset+1] & 0xff) <<16) |
    ((hash[offset+2] & 0xff) <<8) |
    ((hash[offset+3] & 0xff))
    otp = binary % 1000000
    result = otp.to_s
    while (result.length < @codedigit)
      result = "0" + result;
    end
    return result
  end
end

# トークン情報ロード
# token.cfg ファイルからロード
def read_config
  f = File::open('token.cfg')
  line = f.gets
  @token_id = line.split(',')[0]
  @shared_secret = line.split(',')[1]
  f.close
end

# エラー表示
def show_error(message)
  puts "***** #{message} *****"
  puts $!
  puts "***** stack trace *****"
  $@.each { |e| puts e }
end

# バナー表示
def show_menu
  puts "===== HOTP TimeBase Token ====="
end

# Byte 配列変換
def convert_byte(text)
  byte = ["%064b" % text.to_i].pack("B*")
  return byte
end

# === メイン処理
def main
  show_menu
  read_config
  @sec = Base64.decode64(@shared_secret)
  @moving_factor = Time.now.to_i / 30
  @mf = convert_byte(@moving_factor)
  @codedigit = 6
  otp_client = OtpAlgorithm.new(@sec, @mf, @codedigit)
  otp = otp_client.generate_otp
  puts "TokenID = #{@token_id}"
  puts "OTP = #{otp}"
end

if __FILE__ == $0
  main
end