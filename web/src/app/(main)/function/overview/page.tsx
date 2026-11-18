"use client";

import * as React from "react";

import {
  BotIcon,
  CpuIcon,
  DatabaseIcon,
  GitBranchIcon,
  GlobeIcon,
  HardDriveIcon,
  MemoryStickIcon,
  MicroscopeIcon,
  MonitorSmartphoneIcon,
  NetworkIcon,
  ShieldCheckIcon,
  SmartphoneIcon,
  TerminalIcon,
  WrenchIcon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cn } from "@/lib/utils";

/* ============ 数据（v1.0.1 扩展规划：静态展示，后续接后端） ============ */

type AssetCapability = {
  type: string;
  asset: string;
  icon: React.ComponentType<{ className?: string }>;
  stage: "P0" | "P1" | "P2" | "P3" | "P4" | "P5";
  capability: string;
  dynamic?: string;
};

const ASSET_CAPABILITIES: AssetCapability[] = [
  {
    type: "web",
    asset: "Web 站点",
    icon: GlobeIcon,
    stage: "P0",
    capability: "容器沙箱全链路：URL/域名/IP/端口 · 漏洞挖掘 · 流量记录",
    dynamic: "✅ 已跑通（真机 e2e）",
  },
  {
    type: "code_repo",
    asset: "代码仓库",
    icon: GitBranchIcon,
    stage: "P0",
    capability: "git 拉取 · SAST/SCA/Secret · code_verify 静态→动态闭环",
    dynamic: "✅ 静态可达 · 动态复用 Web",
  },
  {
    type: "windows_app",
    asset: "Windows 程序",
    icon: MonitorSmartphoneIcon,
    stage: "P2",
    capability: "MCP Windows 节点：进程/文件/注册表/服务/网络行为/畸形输入",
    dynamic: "✅ 本机安装 · 容器化动态（GUI 受限）",
  },
  {
    type: "firmware",
    asset: "IoT 固件",
    icon: CpuIcon,
    stage: "P2",
    capability: "binwalk 解包 · 密钥/配置提取 · 静态指纹",
    dynamic: "⭕ 动态需 ARM 主机（未排期）",
  },
  {
    type: "android",
    asset: "Android",
    icon: SmartphoneIcon,
    stage: "P3",
    capability: "MobSF 静态（APK 解包/权限/组件/证书/敏感串/已知漏洞）",
    dynamic: "✅ MCP adb 模拟器动态（可选）",
  },
  {
    type: "ios",
    asset: "iOS",
    icon: SmartphoneIcon,
    stage: "P3",
    capability: "MobSF 静态（IPA 解包/plist/entitlements/Mach-O 元数据）",
    dynamic: "⭕ 动态需越狱/macOS（未排期）",
  },
  {
    type: "ai_app",
    asset: "AI 原生应用",
    icon: BotIcon,
    stage: "P4",
    capability: "AI-Infra-Guard 外挂：Agent/Skills/MCP/Infra Scan + LLM Jailbreak Eval",
    dynamic: "✅ 外挂引擎（独立服务）",
  },
];

type NodeStatus = {
  id: string;
  name: string;
  kind: "container" | "mcp" | "external" | "builtin";
  status: "online" | "offline" | "pending";
  detail: string;
  badge?: string;
};

const NODE_STATUSES: NodeStatus[] = [
  {
    id: "container-web",
    name: "容器沙箱（Linux）",
    kind: "container",
    status: "online",
    detail: "web · code · firmware 静态",
  },
  {
    id: "mcp-win",
    name: "MCP Windows 执行节点",
    kind: "mcp",
    status: "pending",
    detail: "pc_assess_* · adb_*（待接入 P2/P3）",
    badge: "规划",
  },
  {
    id: "mobsf",
    name: "MobSF 移动静态引擎",
    kind: "external",
    status: "pending",
    detail: "APK / IPA 静态分析（P3 接入）",
    badge: "规划",
  },
  {
    id: "ai-guard",
    name: "AI-Infra-Guard 引擎",
    kind: "external",
    status: "pending",
    detail: "AI 原生应用安全检测（P4 接入）",
    badge: "规划",
  },
];

const STAGE_LABEL: Record<string, string> = {
  P0: "P0",
  P1: "P1",
  P2: "P2",
  P3: "P3",
  P4: "P4",
  P5: "P5",
};

/* ============ 小组件 ============ */

function StatusDot({ status }: { status: NodeStatus["status"] }) {
  const cls =
    status === "online"
      ? "bg-emerald-500"
      : status === "offline"
        ? "bg-red-500"
        : "bg-amber-500/70";
  return <span className={cn("inline-block size-2 rounded-full", cls)} />;
}

function NodeKindIcon({ kind }: { kind: NodeStatus["kind"] }) {
  if (kind === "container") return <HardDriveIcon className="size-4" />;
  if (kind === "mcp") return <TerminalIcon className="size-4" />;
  return <ShieldCheckIcon className="size-4" />;
}

function StageBadge({ stage }: { stage: string }) {
  const tone =
    stage === "P0"
      ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300"
      : stage === "P4"
        ? "bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300"
        : "bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300";
  return <Badge className={cn("font-mono text-[11px]", tone)}>{STAGE_LABEL[stage] ?? stage}</Badge>;
}

/* ============ 页面 ============ */

export default function OverviewPage() {
  return (
    <div className="flex flex-col gap-5">
      {/* 标题 */}
      <div>
        <h1 className="text-xl font-semibold tracking-tight">扩展能力总览</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          v1.0.1 起规划的多资产类型扩展：二进制（Windows 程序 + IoT 固件）· 移动端（MobSF 静态 + adb 动态）·
          代码审计 · AI 原生应用。核心引擎保持零回归，新增执行节点与外挂引擎。
        </p>
      </div>

      {/* ① 资产能力矩阵 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2">
            <DatabaseIcon data-icon="inline-start" className="size-4" /> 资产能力矩阵
          </CardTitle>
          <CardDescription>首期可达能力与进入里程碑。动态执行标注真实边界，防过度承诺。</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-40">资产类型</TableHead>
                <TableHead className="w-20">路线</TableHead>
                <TableHead>首期能力</TableHead>
                <TableHead>动态执行</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {ASSET_CAPABILITIES.map((c) => (
                <TableRow key={c.type}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <c.icon className="size-4 text-muted-foreground" />
                      <span className="font-medium">{c.asset}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <StageBadge stage={c.stage} />
                  </TableCell>
                  <TableCell className="max-w-xl text-xs leading-relaxed text-muted-foreground">
                    {c.capability}
                  </TableCell>
                  <TableCell className="text-xs">{c.dynamic}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* ② 执行节点状态 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2">
            <NetworkIcon data-icon="inline-start" className="size-4" /> 执行节点状态
          </CardTitle>
          <CardDescription>容器沙箱在服务端；MCP 节点与引擎接入后显示实时状态（当前为规划占位）。</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2">
          {NODE_STATUSES.map((n) => (
            <div
              key={n.id}
              className={cn(
                "flex items-start gap-3 rounded-lg border p-3",
                n.status === "online" ? "border-emerald-500/40 bg-emerald-500/5" : "border-border bg-card",
              )}
            >
              <div className="mt-0.5 text-muted-foreground">
                <NodeKindIcon kind={n.kind} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="truncate text-sm font-medium">{n.name}</span>
                  <StatusDot status={n.status} />
                  {n.badge ? (
                    <Badge variant="secondary" className="text-[10px]">
                      {n.badge}
                    </Badge>
                  ) : null}
                </div>
                <p className="mt-0.5 truncate text-xs text-muted-foreground">{n.detail}</p>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* ③ 外挂引擎接入（MobSF / AI-Infra-Guard） */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2">
            <MemoryStickIcon data-icon="inline-start" className="size-4" /> 外挂引擎接入
          </CardTitle>
          <CardDescription>独立服务通过工具封装接入，检测结果统一收敛为 finding（vulnclass 扩展）。</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2">
          <div className="flex items-start gap-3 rounded-lg border p-3">
            <MicroscopeIcon className="mt-0.5 size-4 text-muted-foreground" />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">MobSF 移动安全框架</span>
                <Badge variant="secondary" className="text-[10px]">
                  静态
                </Badge>
              </div>
              <p className="mt-0.5 text-xs text-muted-foreground">
                APK / IPA 静态分析：权限、组件、证书、敏感字符串、已知漏洞 → mobsf_scan findings
              </p>
            </div>
          </div>
          <div className="flex items-start gap-3 rounded-lg border p-3">
            <BotIcon className="mt-0.5 size-4 text-muted-foreground" />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">Tencent AI-Infra-Guard</span>
                <Badge variant="secondary" className="text-[10px]">
                  外挂
                </Badge>
              </div>
              <p className="mt-0.5 text-xs text-muted-foreground">
                Agent / Skills / MCP / Infra Scan + LLM Jailbreak Eval → ai_scan_* findings
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* ④ 里程碑 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2">
            <WrenchIcon data-icon="inline-start" className="size-4" /> 里程碑
          </CardTitle>
          <CardDescription>按依赖顺序推进；红线贯穿全程：禁止删除数据 · fail-closed · 凭证保险库审计。</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            {(["P0 代码审计", "P1 前端+分流", "P2 Windows/固件", "P3 移动端（MobSF+adb）", "P4 AI 集成", "P5 收束"] as const).map(
              (m, i) => (
                <Badge key={m} variant="outline" className="font-mono text-[11px]">
                  {m}
                </Badge>
              ),
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}