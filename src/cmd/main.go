package main

import (
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
)

func main() {}
func init() {
    // Plugin authors can use any one of four entrypoints, such as
    // `proxywasm.SetVMContext`, `proxywasm.SetPluginContext`, or
    // `proxywasm.SetTcpContext`.
    proxywasm.SetHttpContext(func(contextID uint32) types.HttpContext {
      return &httpContext{}
    })
}
type httpContext struct {
    types.DefaultHttpContext
}
func (*httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action  {
    proxywasm.LogInfo("Hello, world!")
    return types.ActionContinue
}