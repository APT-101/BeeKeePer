"use client";

import * as React from "react";

import { ChevronDownIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";

type SectionInfo = { name: string; count: number };
type ReportView = {
  app: Record<string, unknown>;
  sections: SectionInfo[];
  details: Record<string, unknown>;
};

// MobSF 报告章节的中文说明（展示名 + 一句话用途）
const SECTION_LABELS: Record<string, string> = {
  manifest_analysis: "Manifest 分析（组件导出/权限声明/安全配置）",
  code_analysis: "代码分析（API 误用/加密弱点/危险调用）",
  binary_analysis: "二进制分析（native 库检查）",
  secrets: "硬编码密钥/凭证",
  permissions: "权限清单",
  urls: "URL 收集",
  domains: "域名",
  emails: "邮箱",
  firebase_urls: "Firebase 暴露",
  certificate_analysis: "证书分析",
  exported_activities: "导出 Activity",
  exported_count: "导出组件计数",
  exported_receivers: "导出 Receiver",
  exported_services: "导出 Service",
  exported_providers: "导出 Provider",
  activities: "Activity 清单",
  services: "Service 清单",
  providers: "Provider 清单",
  receivers: "Receiver 清单",
  trackers: "追踪器",
  sbom: "SBOM 组件清单",
  apkid: "APKiD 打包器识别",
  networks_security: "网络安全配置",
  network_security: "网络安全配置",
  malware_permissions: "恶意权限特征",
  appsec: "安全评分",
  average_cvss: "平均 CVSS",
  virus_total: "VirusTotal",
  playstore_details: "Play 商店信息",
  libraries: "依赖库",
  dwd_dir: " Drozer/调试目录",
  file_analysis: "文件分析",
  logs: "日志",
};

function sectionLabel(name: string): string {
  return SECTION_LABELS[name] ?? name;
}

// 条目通用渲染：object 转 key/value 行；标量原样
function EntryRows({ entry }: { entry: unknown }) {
  if (entry == null) return null;
  if (typeof entry !== "object") {
    return <div className="text-sm text-muted-foreground">{String(entry)}</div>;
  }
  const obj = entry as Record<string, unknown>;
  return (
    <div className="grid gap-1 text-xs">
      {Object.entries(obj)
        .filter(([, v]) => v != null && JSON.stringify(v) !== "[]" && JSON.stringify(v) !== "{}")
        .map(([k, v]) => (
          <div key={k} className="flex gap-2">
            <span className="shrink-0 font-medium text-foreground/70">{k}</span>
            <span className="min-w-0 break-all text-muted-foreground">
              {typeof v === "object" ? JSON.stringify(v) : String(v)}
            </span>
          </div>
        ))}
    </div>
  );
}

// 关键章节折叠卡：条目列表 + 展开控制（默认收起，防大列表刷屏）
function SectionCard({ name, entries }: { name: string; entries: unknown[] }) {
  const [open, setOpen] = React.useState(false);
  const shown = open ? entries : entries.slice(0, 5);
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">
          {sectionLabel(name)}
          <Badge variant="secondary" className="ml-2">
            {entries.length} 条
          </Badge>
        </CardTitle>
        {entries.length > 5 && (
          <Button variant="ghost" size="sm" onClick={() => setOpen(!open)}>
            {open ? "收起" : `展开全部 ${entries.length} 条`}
            <ChevronDownIcon className={`ml-1 h-4 w-4 transition-transform ${open ? "rotate-180" : ""}`} />
          </Button>
        )}
      </CardHeader>
      <CardContent className="space-y-3">
        {shown.map((e, i) => (
          <div key={i} className="rounded-md border p-2">
            <EntryRows entry={e} />
          </div>
        ))}
        {!open && entries.length > 5 && (
          <div className="text-xs text-muted-foreground">… 其余 {entries.length - 5} 条</div>
        )}
      </CardContent>
    </Card>
  );
}

// 标量型统计（exported_count / average_cvss / appsec 等对象或数字）
function StatCard({ name, value }: { name: string; value: unknown }) {
  const summary =
    typeof value === "object" && value != null
      ? Object.entries(value as Record<string, unknown>)
          .filter(([, v]) => typeof v === "string" || typeof v === "number" || typeof v === "boolean")
          .slice(0, 4)
          .map(([k, v]) => `${k}: ${v}`)
          .join("　")
      : String(value);
  return (
    <Card>
      <CardHeader className="pb-1">
        <CardTitle className="text-xs font-medium text-muted-foreground">{sectionLabel(name)}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="text-sm font-medium">{summary || "-"}</div>
      </CardContent>
    </Card>
  );
}

export function MobsfReportTab({ taskId }: { taskId: string }) {
  const [view, setView] = React.useState<ReportView | null>(null);
  const [err, setErr] = React.useState("");
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    api
      .getMobsfReport(taskId)
      .then((r) => {
        if (alive) setView(r);
      })
      .catch((e: unknown) => {
        if (alive) setErr(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [taskId]);

  if (loading) return <div className="p-6 text-sm text-muted-foreground">加载 MobSF 报告…</div>;
  if (err)
    return (
      <div className="p-6 text-sm text-muted-foreground">
        {err}
        <div className="mt-2 text-xs">在任务会话里发送指令让 agent 执行 mobsf_scan，即可生成报告。</div>
      </div>
    );
  if (!view) return null;

  const detailKeys = ["manifest_analysis", "code_analysis", "binary_analysis", "secrets", "permissions", "urls", "firebase_urls", "certificate_analysis"];
  const statKeys = ["exported_count", "average_cvss", "appsec"];
  const shownSections = new Set([...detailKeys, ...statKeys]);

  return (
    <div className="flex flex-1 flex-col gap-4 overflow-y-auto p-4">
      {/* 应用信息 */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">应用信息</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-2 text-xs md:grid-cols-4">
          {Object.entries(view.app).map(([k, v]) => (
            <div key={k} className="min-w-0">
              <div className="text-muted-foreground">{k}</div>
              <div className="break-all font-medium">{String(v ?? "-")}</div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* 统计卡 */}
      <div className="grid gap-3 md:grid-cols-3">
        {statKeys.map((k) => {
          const v = view.details[k];
          if (v == null) return null;
          return <StatCard key={k} name={k} value={v} />;
        })}
      </div>

      {/* 关键章节（裁剪条目） */}
      <div className="grid gap-3 lg:grid-cols-2">
        {detailKeys.map((k) => {
          const v = view.details[k];
          if (v == null || (Array.isArray(v) && v.length === 0)) return null;
          const arr = Array.isArray(v) ? v : [v];
          return <SectionCard key={k} name={k} entries={arr} />;
        })}
      </div>

      {/* 其余章节总览（名称 + 条目数，点击不可展开——完整数据以报告 JSON 为准） */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">全部章节</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {view.sections
            .filter((s) => !shownSections.has(s.name))
            .map((s) => (
              <Badge key={s.name} variant="outline" className="text-xs">
                {sectionLabel(s.name)} · {s.count}
              </Badge>
            ))}
        </CardContent>
      </Card>
    </div>
  );
}
