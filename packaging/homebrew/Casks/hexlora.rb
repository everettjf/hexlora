cask "hexlora" do
  version "1.3.2"
  sha256 "86f0210d0fa12fa555114d449be0823dbe3188797e8b2d58c248c5b15b444828"

  url "https://github.com/everettjf/homebrew-tap/releases/download/hexlora-v#{version}/Hexlora-#{version}-macos.zip"
  name "Hexlora"
  desc "Application, package, and binary inspection workbench"
  homepage "https://atomsprout.com/hexlora/"

  depends_on arch: :arm64
  depends_on macos: :ventura

  app "Hexlora.app"

  zap trash: "~/Library/Application Support/Hexlora"
end
