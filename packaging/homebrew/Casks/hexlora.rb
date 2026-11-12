cask "hexlora" do
  version "1.1.22"
  sha256 "bde9111ab11e781397c99eab6d955c0e34e648cb36b43984c50536fd711b3a03"

  url "https://github.com/everettjf/homebrew-tap/releases/download/hexlora-v#{version}/Hexlora-#{version}-macos.zip"
  name "Hexlora"
  desc "Application, package, and binary inspection workbench"
  homepage "https://atomsprout.com/hexlora/"

  depends_on macos: :ventura
  depends_on arch: :arm64

  app "Hexlora.app"

  zap trash: "~/Library/Application Support/Hexlora"
end
