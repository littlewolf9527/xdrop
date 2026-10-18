# XDROP console

Requires Node.js and npm. Use npm from this directory.

```sh
npm ci --ignore-scripts
npm run build
cd ../controller
go build -tags webui ./cmd/xdrop-controller
```

The generated `controller/core/webui/build/` and `console/node_modules/` are ignored.
The default Go build serves the existing placeholder. A `webui` build requires the generated frontend.

`npm run dev` serves the development mock on 127.0.0.1:5173.
Use `admin` or `operator` with `example-password-1`.
`npm run dev:real` proxies `/api` to the local controller on 127.0.0.1:18080.
The mock is loaded only by the development server and is excluded from production.

```sh
npx vue-tsc --noEmit
npx vitest run
node scripts/contract-check.mjs http://127.0.0.1:18080
```

Set `CONTRACT_USERNAME` and `CONTRACT_PASSWORD` for the read-only contract check.
It logs in independently, reads GET responses and the three initial SSE classes, then disconnects.
`CONTRACT_CONTROLS=1` also checks the two deliberately invalid non-array paths;
`CONTRACT_CONTROLS=lab` adds the invalid node path when a sampled node exists.

第三方清单由实际构建产物生成，构建机必须提供 `go` 与 `git`。版本取仓库 `git describe --tags --always --dirty`；Go 模块通过不带标签的 `go list` 枚举。`node scripts/third-party.mjs --check` 在 `$TMPDIR` 内独立构建并核对浏览器与字体集合；设置 `C5D_BINARY` 可同时核对控制器二进制模块与 Go 版本。
