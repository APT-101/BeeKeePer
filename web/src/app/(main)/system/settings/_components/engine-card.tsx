"use client";

import * as React from "react";

import { PlugIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";

type MobsfConfig = {
  api_url: string;
  configured: boolean;
  api_key_masked: string;
};

type ProbeState = { busy: boolean; ok: boolean | null; reason: string };

// 「外挂引擎」卡片：外部引擎（MobSF / AI-Infra-Guard / …）的接入配置统一在此
// 管理。每个引擎一节，结构统一（API 地址 + API Key + 测试连接 + 状态灯）；
// 新引擎接入时往下加一节即可。后端：/api/mobsf/config、/api/mobsf/test。
export function EnginesCard() {
  // MobSF
  const [mobsfUrl, setMobsfUrl] = React.useState("");
  const [mobsfKeyMasked, setMobsfKeyMasked] = React.useState("");
  const [mobsfKeyInput, setMobsfKeyInput] = React.useState("");
  const [mobsfConfigured, setMobsfConfigured] = React.useState(false);
  const [mobsfLoaded, setMobsfLoaded] = React.useState(false);
  const [savingMobsf, setSavingMobsf] = React.useState(false);
  const [mobsfProbe, setMobsfProbe] = React.useState<ProbeState>({ busy: false, ok: null, reason: "" });

  const loadMobsf = React.useCallback(() => {
    api
      .mobsfConfig()
      .then((c) => {
        setMobsfUrl(c.api_url);
        setMobsfKeyMasked(c.api_key_masked);
        setMobsfConfigured(c.configured);
        setMobsfLoaded(true);
      })
      .catch(() => setMobsfLoaded(true));
  }, []);

  React.useEffect(() => {
    loadMobsf();
  }, [loadMobsf]);

  const saveMobsf = () => {
    const url = mobsfUrl.trim();
    const key = mobsfKeyInput.trim();
    if (url && !/^https?:\/\//.test(url)) {
      toast.error("API 地址必须以 http:// 或 https:// 开头");
      return;
    }
    if (!url && !key) {
      toast.error("请填写 API 地址或 API Key");
      return;
    }
    setSavingMobsf(true);
    api
      .saveMobsfConfig(url, key)
      .then((c) => {
        setMobsfUrl(c.api_url);
        setMobsfKeyMasked(c.api_key_masked);
        setMobsfConfigured(c.configured);
        setMobsfKeyInput("");
        setMobsfProbe({ busy: false, ok: null, reason: "" });
        toast.success("已保存 MobSF 接入配置");
      })
      .catch((e) => toast.error("保存失败：" + (e as Error).message))
      .finally(() => setSavingMobsf(false));
  };

  const testMobsf = () => {
    setMobsfProbe({ busy: true, ok: null, reason: "探测中…" });
    api
      .testMobsf()
      .then((r) => setMobsfProbe({ busy: false, ok: r.ok, reason: r.reason }))
      .catch((e) => setMobsfProbe({ busy: false, ok: false, reason: (e as Error).message }));
  };

  const probeDot = (p: ProbeState) =>
    p.ok === true ? (
      <span className="text-emerald-500">● 已连通</span>
    ) : p.ok === false ? (
      <span className="text-red-500">● {p.reason}</span>
    ) : (
      <span className="text-muted-foreground">● {p.reason || "未测试"}</span>
    );

  // ---- M2 动态轨：DroidBridge 反连网关 ----
  type MobileDevice = {
    deviceId: string;
    model: string;
    androidVersion: string;
    rooted: boolean;
    connectedFor: number;
    occupiedBy: string;
  };
  const [mobileCfg, setMobileCfg] = React.useState<{
    configured: boolean;
    token_masked: string;
    online_devices: MobileDevice[];
  } | null>(null);
  const [mobileLoaded, setMobileLoaded] = React.useState(false);
  const [rotating, setRotating] = React.useState(false);

  const loadMobile = React.useCallback(() => {
    api
      .getMobileConfig()
      .then((c) => {
        setMobileCfg(c);
        setMobileLoaded(true);
      })
      .catch(() => setMobileLoaded(true));
  }, []);

  React.useEffect(() => {
    loadMobile();
    const timer = setInterval(loadMobile, 10000); // 设备在线状态 10s 自动刷新
    return () => clearInterval(timer);
  }, [loadMobile]);

  const rotateMobileToken = () => {
    setRotating(true);
    api
      .rotateMobileToken()
      .then((c) => {
        setMobileCfg((prev) =>
          prev
            ? {
                ...prev,
                configured: c.configured,
                token_masked: c.token_masked,
                online_devices: c.online_devices,
              }
            : prev
        );
        toast.success("配对 token 已更换——旧 token 立即失效，设备需重填后重新反连");
      })
      .catch((e) => toast.error("更换失败：" + (e as Error).message))
      .finally(() => setRotating(false));
  };

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <PlugIcon className="size-4" />
          外挂引擎
        </CardTitle>
        <CardDescription>
          外部引擎的接入配置统一在此管理：填 API 地址与 Key，保存后用「测试连接」验证连通性与
          Key 有效性。未配置的引擎不影响其它功能——对应能力（如移动静态扫描）以工具形态按需出现。
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-6">
        {/* ---- MobSF（移动静态分析）---- */}
        <div className="flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <Label className="text-sm font-semibold">MobSF（移动静态分析）</Label>
            <span
              className={`text-xs ${mobsfConfigured ? "text-emerald-500" : "text-muted-foreground"}`}
            >
              {mobsfConfigured ? `已配置（Key ${mobsfKeyMasked}）` : "未配置"}
            </span>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="mobsf-url" className="text-muted-foreground text-sm font-normal">
              API 地址
            </Label>
            <Input
              id="mobsf-url"
              value={mobsfUrl}
              placeholder="http://host:8000（docker mobsfsec/mobsf 默认 8000）"
              disabled={!mobsfLoaded || savingMobsf}
              onChange={(e) => setMobsfUrl(e.target.value)}
              className="font-mono text-xs"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="mobsf-key" className="text-muted-foreground text-sm font-normal">
              API Key {mobsfConfigured && mobsfKeyMasked && (
                <span className="ml-1 text-emerald-500">已配置（{mobsfKeyMasked}）</span>
              )}
            </Label>
            <Input
              id="mobsf-key"
              type="password"
              autoComplete="off"
              value={mobsfKeyInput}
              placeholder={mobsfConfigured ? "已配置（输入新 Key 则覆盖）" : "输入 REST API Key"}
              disabled={!mobsfLoaded || savingMobsf}
              onChange={(e) => setMobsfKeyInput(e.target.value)}
            />
          </div>
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <Button size="sm" onClick={saveMobsf} disabled={!mobsfLoaded || savingMobsf}>
                保存
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={testMobsf}
                disabled={!mobsfLoaded || mobsfProbe.busy}
              >
                {mobsfProbe.busy ? "测试中…" : "测试连接"}
              </Button>
            </div>
            <p className="text-muted-foreground text-xs">{probeDot(mobsfProbe)}</p>
          </div>
          <p className="text-muted-foreground text-xs leading-relaxed">
            MobSF 由你自行部署（例如{" "}
            <code className="font-mono">docker run -it --rm -p 8000:8000 mobsfsec/mobsf</code>），
            REST API Key 见部署实例的环境配置。接入后，任务里的 APK/IPA 附件可用
            <b> mobsf_scan</b> 工具交给它做全量静态扫描（manifest 分析 / 代码规则 / 硬编码密钥），
            结果自动落 finding 与组件。
          </p>
        </div>

        {/* ---- M2 动态轨：DroidBridge 反连网关 ---- */}
        <div className="border-t pt-4 flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <Label className="text-sm font-semibold">DroidBridge（移动动态分析 · 设备反连）</Label>
            <span
              className={`text-xs ${
                mobileCfg?.configured && (mobileCfg.online_devices?.length ?? 0) > 0
                  ? "text-emerald-500"
                  : "text-muted-foreground"
              }`}
            >
              {mobileCfg?.configured
                ? `${mobileCfg.online_devices?.length ?? 0} 台设备在线`
                : "未配置"}
            </span>
          </div>
          <p className="text-muted-foreground text-xs leading-relaxed">
            在 root Android 设备上安装 DroidBridge APK，反连地址填{" "}
            <code className="font-mono">ws://&lt;控制台IP&gt;:8787/ws/droid</code>，token 填下方配对令牌。
            设备上线后，任务里的 <b>mobile_exec / mobile_screencap / mobile_push</b> 等工具即可操作真机
            （安装运行应用、frida hook、抓包、拉取文件），发现自动落 finding。
          </p>
          <div className="flex flex-col gap-1.5">
            <Label className="text-muted-foreground text-sm font-normal">
              配对 Token {mobileCfg?.configured && mobileCfg.token_masked && (
                <span className="ml-1 font-mono text-emerald-500">
                  已配置（{mobileCfg.token_masked}）
                </span>
              )}
            </Label>
            <div className="flex items-center gap-2">
              <Button size="sm" variant="outline" onClick={rotateMobileToken} disabled={!mobileLoaded || rotating}>
                {rotating ? "更换中…" : "更换配对 Token"}
              </Button>
              <Button size="sm" variant="ghost" onClick={loadMobile} disabled={!mobileLoaded}>
                刷新设备列表
              </Button>
            </div>
          </div>
          {(mobileCfg?.online_devices?.length ?? 0) > 0 && (
            <div className="rounded-md border p-2 flex flex-col gap-2">
              {mobileCfg!.online_devices.map((d) => (
                <div key={d.deviceId} className="flex items-center justify-between text-xs">
                  <div className="min-w-0">
                    <span className="font-medium">{d.model}</span>
                    <span className="ml-2 text-muted-foreground">
                      Android {d.androidVersion} · root={String(d.rooted)} · 在线 {d.connectedFor}s
                      {d.occupiedBy ? ` · 被任务 ${d.occupiedBy} 占用` : ""}
                    </span>
                  </div>
                  <span className="font-mono text-muted-foreground">{d.deviceId.slice(0, 8)}…</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ---- AI-Infra-Guard（预留）---- */}
        <div className="border-t pt-4">
          <div className="flex items-center justify-between">
            <Label className="text-sm font-semibold">AI-Infra-Guard（AI 基础设施审计）</Label>
            <span className="text-muted-foreground text-xs">规划中</span>
          </div>
          <p className="text-muted-foreground mt-1 text-xs leading-relaxed">
            接入形态与 MobSF 相同（API 地址 + Key + 测试连接），能力面为 AI
            基础设施（Agent/Skills/MCP）的扫描与评估。待后端集成上线后开放配置。
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
