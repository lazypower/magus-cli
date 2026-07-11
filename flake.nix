{
  description = "magus - Butane reconciler for Magus";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        packages.magus = pkgs.buildGoModule {
          pname = "magus";
          version = "dev";

          src = self;

          vendorHash = "sha256-9iT/CpLEifaZAda7OM1Q9XoRxm3GYlggdyxg8DIxRMU=";

          subPackages = [ "cmd/magus" ];

          meta = with pkgs.lib; {
            description = "Day-2 reconciler for bootc / Fedora CoreOS hosts";
            homepage = "https://github.com/lazypower/magus-cli";
            license = licenses.asl20;
            mainProgram = "magus";
          };
        };

        packages.default = self.packages.${system}.magus;

        apps.magus = flake-utils.lib.mkApp {
          drv = self.packages.${system}.magus;
          name = "magus";
        };

        apps.default = self.apps.${system}.magus;
      });
}
