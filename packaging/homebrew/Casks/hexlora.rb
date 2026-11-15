cask "hexlora" do
  version "1.1.23"
  sha256 "06824048be177b07cf4c7c4bc9cb2f45a7c54491a3be3fd21a0029efc44f2031"

  url "https://github.com/everettjf/homebrew-tap/releases/download/hexlora-v#{version}/Hexlora-#{version}-macos.zip"
  name "Hexlora"
  desc "Application, package, and binary inspection workbench"
  homepage "https://atomsprout.com/hexlora/"

  depends_on arch: :arm64
  depends_on macos: :ventura

  app "Hexlora.app"

  zap trash: "~/Library/Application Support/Hexlora"
end
