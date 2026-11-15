cask "hexlora" do
  version "1.2.0"
  sha256 "653a1076b08e8a9708c2eb7778c8ab4a30f65b98d47378b3114f4b9a7d0fdbf0"

  url "https://github.com/everettjf/homebrew-tap/releases/download/hexlora-v#{version}/Hexlora-#{version}-macos.zip"
  name "Hexlora"
  desc "Application, package, and binary inspection workbench"
  homepage "https://atomsprout.com/hexlora/"

  depends_on arch: :arm64
  depends_on macos: :ventura

  app "Hexlora.app"

  zap trash: "~/Library/Application Support/Hexlora"
end
