cask "hexlora" do
  version "1.1.19"
  sha256 "56f6108fb872939f14d6b59cf7e2620651263814fbcb56376724d3e196b4db9e"

  url "https://github.com/everettjf/homebrew-tap/releases/download/hexlora-v#{version}/Hexlora-#{version}-macos.zip"
  name "Hexlora"
  desc "Application, package, and binary inspection workbench"
  homepage "https://github.com/everettjf/hexlora"

  depends_on macos: :ventura
  depends_on arch: :arm64

  app "Hexlora.app"

  zap trash: "~/Library/Application Support/Hexlora"
end
