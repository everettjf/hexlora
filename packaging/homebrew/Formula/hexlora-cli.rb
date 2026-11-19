class HexloraCli < Formula
  desc "Static application, package, and binary inspection workbench"
  homepage "https://atomsprout.com/hexlora/"
  url "https://github.com/everettjf/homebrew-tap/releases/download/hexlora-v1.3.3/hexlora-cli-1.3.3-aarch64-apple-darwin.tar.gz"
  sha256 "785496ab5bfc270d04d5b7ff5690f2a07a731b2a85a84f3d1dab09acd08982f1"
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
