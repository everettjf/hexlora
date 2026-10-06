cask "hexlora" do
  version "1.1.20"
  sha256 "06b0229f7c4ec61f7908168bb735fa5d8d4872df9830fb755834106f33f8556e"

  url "https://github.com/everettjf/homebrew-tap/releases/download/hexlora-v#{version}/Hexlora-#{version}-macos.zip"
  name "Hexlora"
  desc "Application, package, and binary inspection workbench"
  homepage "https://github.com/everettjf/hexlora"

  depends_on macos: :ventura
  depends_on arch: :arm64

  app "Hexlora.app"

  zap trash: "~/Library/Application Support/Hexlora"
end
