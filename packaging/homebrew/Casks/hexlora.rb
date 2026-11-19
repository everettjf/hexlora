cask "hexlora" do
  version "1.3.0"
  sha256 "75832872ae3af244d2b1e19128a4f7c21fb81cf5b3211150e61989d300d764b8"

  url "https://github.com/everettjf/homebrew-tap/releases/download/hexlora-v#{version}/Hexlora-#{version}-macos.zip"
  name "Hexlora"
  desc "Application, package, and binary inspection workbench"
  homepage "https://atomsprout.com/hexlora/"

  depends_on arch: :arm64
  depends_on macos: :ventura

  app "Hexlora.app"

  zap trash: "~/Library/Application Support/Hexlora"
end
