cask "hexlora" do
  version "1.1.17"
  sha256 "dda107695eaf9f88dadf736b539ffa630ac30b6f274a2d28113495ab6ded8182"

  url "https://github.com/everettjf/homebrew-tap/releases/download/hexlora-v#{version}/Hexlora-#{version}-macos.zip"
  name "Hexlora"
  desc "Application, package, and binary inspection workbench"
  homepage "https://github.com/everettjf/hexlora"

  depends_on macos: :ventura
  depends_on arch: :arm64

  app "Hexlora.app"

  zap trash: "~/Library/Application Support/Hexlora"
end
