cask "hexlora" do
  version "1.1.21"
  sha256 "1bb311135424dd0aa4c1e7f58afba0664f5b38c3722a1e427df689c291190aea"

  url "https://github.com/everettjf/homebrew-tap/releases/download/hexlora-v#{version}/Hexlora-#{version}-macos.zip"
  name "Hexlora"
  desc "Application, package, and binary inspection workbench"
  homepage "https://github.com/everettjf/hexlora"

  depends_on macos: :ventura
  depends_on arch: :arm64

  app "Hexlora.app"

  zap trash: "~/Library/Application Support/Hexlora"
end
