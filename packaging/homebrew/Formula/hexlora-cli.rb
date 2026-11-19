class HexloraCli < Formula
  desc "Static application, package, and binary inspection workbench"
  homepage "https://atomsprout.com/hexlora/"
  url "https://github.com/everettjf/homebrew-tap/releases/download/hexlora-v1.3.0/hexlora-cli-1.3.0-aarch64-apple-darwin.tar.gz"
  sha256 "df013daeb522b77a917f86fb3f5b41a9ee2c7f3e7e9678cd91de78f0bb2a3d7a"
  license "Apache-2.0"

  depends_on arch: :arm64

  def install
    bin.install "hexlora-cli"
  end

  test do
    (testpath/"fixture.json").write('{"hexlora":true}')
    output = shell_output("#{bin}/hexlora-cli inspect #{testpath}/fixture.json --json")
    report = JSON.parse(output)
    assert_equal 1, report.fetch("schema_version")
    assert_equal false, report.dig("run", "partial")
  end
end
