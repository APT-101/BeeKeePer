//go:build windows

package server

import (
	"os/exec"
)

// setProcGroup：Windows 开发构建下的占位实现。反编译（IDA 无头）只在
// Linux 部署机上跑；Windows 仅保证编译通过，任务级进程组隔离不生效。
func setProcGroup(cmd *exec.Cmd) {}

// killProcGroup：Windows 开发构建下退化为只杀主进程。
func killProcGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
