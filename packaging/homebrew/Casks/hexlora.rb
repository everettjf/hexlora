cask "hexlora" do
  version "1.2.1"
  sha256 "be84a527b84e02a40491adbdbb4fc3ef42cce30773a81e08aaf7b76d4ffc59fa"

  url "https://github.com/everettjf/homebrew-tap/releases/download/hexlora-v#{version}/Hexlora-#{version}-macos.zip"
  name "Hexlora"
  desc "Application, package, and binary inspection workbench"
  homepage "https://atomsprout.com/hexlora/"

  depends_on arch: :arm64
  depends_on macos: :ventura

  app "Hexlora.app"

  zap trash: "~/Library/Application Support/Hexlora"
end
