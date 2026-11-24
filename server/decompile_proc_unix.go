//go:build !windows

package server

import (
	"os/exec"
	"syscall"
)

// setProcGroup 把子进程放进独立进程组：取消/超时按组杀，idat 会带子进程。
func setProcGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// killProcGroup 按 PGID 杀整个进程组（Linux/Unix 部署路径）。
func killProcGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
